#include "glove/detail/descriptor_acl.hpp"

#include "pi_private_state.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <membership.h>
#    include <sys/acl.h>
#endif

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::run::detail::pi_guest_config;
using glove::run::detail::pi_private_state;
namespace fs = std::filesystem;
constexpr const char* marker_name = ".glove-pi-lease";

static_assert(!std::is_copy_constructible_v<pi_private_state>);
static_assert(!std::is_copy_assignable_v<pi_private_state>);
static_assert(std::is_nothrow_move_constructible_v<pi_private_state>);
static_assert(std::is_nothrow_move_assignable_v<pi_private_state>);

struct fixture {
    fs::path directory;

    fixture() {
#if defined(__APPLE__)
        std::string pattern = "/private/tmp/glove-pi-private-test-XXXXXX";
#else
        std::string pattern = "/tmp/glove-pi-private-test-XXXXXX";
#endif
        if (auto* created = ::mkdtemp(pattern.data())) {
            directory = created;
        }
    }

    fixture(const fixture&) = delete;
    auto operator=(const fixture&) -> fixture& = delete;

    ~fixture() {
        if (!directory.empty()) {
            // Test-owned fixture only; production never uses guessed path deletion.
            std::error_code ignored;
            fs::remove_all(directory, ignored);
        }
    }
};

auto config() -> pi_guest_config {
    return {"{\"providers\":{}}", "{\"extensions\":[],\"skills\":[]}", {}, {}};
}

auto read(const fs::path& path) -> std::string {
    std::ifstream input{path};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

auto mode(const fs::path& path) -> mode_t {
    struct stat info{};
    return ::lstat(path.c_str(), &info) == 0 ? info.st_mode & 07777U : 0;
}

auto path_exists(const fs::path& path) -> bool {
    struct stat info{};
    return ::lstat(path.c_str(), &info) == 0;
}

auto write_fixture(const fs::path& path, std::string_view bytes, mode_t permissions) -> bool {
    const int fd =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, permissions);
    if (fd < 0) {
        return false;
    }
    const auto count = ::write(fd, bytes.data(), bytes.size());
    const bool good = count == static_cast<ssize_t>(bytes.size()) &&
                      ::fchmod(fd, permissions) == 0 && ::fsync(fd) == 0;
    return ::close(fd) == 0 && good;
}

auto stale_fixture(const fs::path& parent, char suffix, std::string_view phase) -> fs::path {
    const auto root = parent / ("run-" + std::string(48, suffix));
    if (::mkdir(root.c_str(), 0700) != 0) {
        return {};
    }
    struct stat info{};
    if (::lstat(root.c_str(), &info) != 0) {
        return {};
    }
    const auto bytes =
        "glove-pi-private-v1\n" + std::to_string(static_cast<std::uintmax_t>(info.st_dev)) + "\n" +
        std::to_string(static_cast<std::uintmax_t>(info.st_ino)) + "\n" + std::string{phase} + "\n";
    return write_fixture(root / marker_name, bytes, 0600) ? root : fs::path{};
}

auto same_signal_action_behavior(
    const struct sigaction& actual, const struct sigaction& saved
) noexcept -> bool {
    constexpr auto flags = static_cast<unsigned int>(
        SA_NOCLDSTOP | SA_NOCLDWAIT | SA_NODEFER | SA_ONSTACK | SA_RESETHAND | SA_RESTART |
        SA_SIGINFO
    );
    if ((static_cast<unsigned int>(actual.sa_flags) & flags) !=
        (static_cast<unsigned int>(saved.sa_flags) & flags)) {
        return false;
    }
    if ((saved.sa_flags & SA_SIGINFO) != 0) {
        if (actual.sa_sigaction != saved.sa_sigaction) {
            return false;
        }
    } else {
        if (actual.sa_handler != saved.sa_handler) {
            return false;
        }
        // sa_mask applies only during a user handler. DFL/IGN invoke none;
        // interceptors can normalize these inert masks without changing delivery.
        if (saved.sa_handler == SIG_DFL || saved.sa_handler == SIG_IGN) {
            return true;
        }
    }
    for (int signal = 1; signal < NSIG; ++signal) {
        const int actual_member = (::sigismember)(&actual.sa_mask, signal);
        const int saved_member = (::sigismember)(&saved.sa_mask, signal);
        if (actual_member < 0 || saved_member < 0 || actual_member != saved_member) {
            return false;
        }
    }
    return true;
}

void fixture_signal_handler(int) {}

void fixture_siginfo_handler(int, siginfo_t*, void*) {}

auto signal_restoration_contract() -> int {
    struct sigaction saved{};
    REQUIRE((::sigemptyset)(&saved.sa_mask) == 0);
    saved.sa_handler = SIG_DFL;
    auto actual = saved;
    REQUIRE((::sigaddset)(&actual.sa_mask, SIGTERM) == 0);
    REQUIRE(same_signal_action_behavior(actual, saved));
    actual.sa_handler = SIG_IGN;
    REQUIRE(!same_signal_action_behavior(actual, saved));
    saved.sa_handler = SIG_IGN;
    REQUIRE(same_signal_action_behavior(actual, saved));
    actual.sa_flags = SA_RESTART;
    REQUIRE(!same_signal_action_behavior(actual, saved));
    actual.sa_flags = 0;
    saved.sa_handler = &fixture_signal_handler;
    actual.sa_handler = &fixture_signal_handler;
    REQUIRE(!same_signal_action_behavior(actual, saved));
    actual.sa_mask = saved.sa_mask;
    REQUIRE(same_signal_action_behavior(actual, saved));
    saved.sa_flags = SA_SIGINFO;
    actual.sa_flags = SA_SIGINFO;
    saved.sa_sigaction = &fixture_siginfo_handler;
    actual.sa_sigaction = &fixture_siginfo_handler;
    REQUIRE(same_signal_action_behavior(actual, saved));
    REQUIRE((::sigaddset)(&actual.sa_mask, SIGTERM) == 0);
    REQUIRE(!same_signal_action_behavior(actual, saved));
    return 0;
}

// This fault affects only this isolated test process, not a guest resource policy.
// The outer test checks restoration even when REQUIRE returns from its inner scope.
class scoped_lease_write_failure {
public:
    explicit scoped_lease_write_failure(bool& restored) noexcept : restored_{restored} {
        if (::getrlimit(RLIMIT_FSIZE, &saved_limit_) != 0 ||
            ::sigaction(SIGXFSZ, nullptr, &saved_action_) != 0) {
            return;
        }
        saved_ = true;
        struct sigaction ignored{};
        ignored.sa_handler = SIG_IGN;
        if ((::sigemptyset)(&ignored.sa_mask) != 0 ||
            ::sigaction(SIGXFSZ, &ignored, nullptr) != 0) {
            return;
        }
        signal_changed_ = true;
        auto zero = saved_limit_;
        zero.rlim_cur = 0;
        if (::setrlimit(RLIMIT_FSIZE, &zero) != 0) {
            return;
        }
        limit_changed_ = true;
        struct rlimit actual_limit{};
        struct sigaction actual_action{};
        ready = ::getrlimit(RLIMIT_FSIZE, &actual_limit) == 0 && actual_limit.rlim_cur == 0 &&
                actual_limit.rlim_max == saved_limit_.rlim_max &&
                ::sigaction(SIGXFSZ, nullptr, &actual_action) == 0 &&
                actual_action.sa_handler == SIG_IGN;
    }

    scoped_lease_write_failure(const scoped_lease_write_failure&) = delete;
    auto operator=(const scoped_lease_write_failure&) -> scoped_lease_write_failure& = delete;

    ~scoped_lease_write_failure() {
        bool good = true;
        if (limit_changed_) {
            good = ::setrlimit(RLIMIT_FSIZE, &saved_limit_) == 0;
        }
        if (signal_changed_) {
            good = (::sigaction(SIGXFSZ, &saved_action_, nullptr) == 0) && good;
        }
        if (saved_) {
            struct rlimit actual_limit{};
            struct sigaction actual_action{};
            good = (::getrlimit(RLIMIT_FSIZE, &actual_limit) == 0 &&
                    actual_limit.rlim_cur == saved_limit_.rlim_cur &&
                    actual_limit.rlim_max == saved_limit_.rlim_max) &&
                   good;
            if (::sigaction(SIGXFSZ, nullptr, &actual_action) != 0) {
                good = false;
            } else {
                good = same_signal_action_behavior(actual_action, saved_action_) && good;
            }
        }
        restored_ = good;
    }

    bool ready = false;

private:
    bool& restored_;
    struct rlimit saved_limit_{};
    struct sigaction saved_action_{};
    bool saved_ = false;
    bool signal_changed_ = false;
    bool limit_changed_ = false;
};

// Enumeration reuses the stream opened before create; the noexcept barrier does
// not open descriptors or allocate paths while observing the partial namespace.
auto count_run_roots(DIR* parent) noexcept -> int {
    ::rewinddir(parent);
    int count = 0;
    for (;;) {
        errno = 0;
        const auto* entry = ::readdir(parent);
        if (entry == nullptr) {
            return errno == 0 ? count : -1;
        }
        if (std::string_view{entry->d_name}.starts_with("run-")) {
            ++count;
        }
    }
}

struct fake_endpoint_owner {
    bool revoked = false;
    bool joined = false;

    void revoke_and_join() noexcept {
        // Synthetic ownership model only: no endpoint, provider, or worker runs.
        revoked = true;
        joined = true;
    }
};

struct rollback_observation {
    DIR* parent = nullptr;
    fake_endpoint_owner endpoint{};
    int calls = 0;
    int roots_before = -1;
    int roots_after_join = -1;

    static void before_cleanup(void* context) noexcept {
        auto& observed = *static_cast<rollback_observation*>(context);
        ++observed.calls;
        observed.roots_before = count_run_roots(observed.parent);
        observed.endpoint.revoke_and_join();
        observed.roots_after_join = count_run_roots(observed.parent);
    }
};

auto creation_rollback_barrier() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    REQUIRE(write_fixture(f.directory / "unrelated", "sibling", 0600));
    const std::unique_ptr<DIR, decltype(&::closedir)> parent{
        ::opendir(f.directory.c_str()), &::closedir
    };
    REQUIRE(parent != nullptr);
    rollback_observation observed{parent.get()};
    const glove::run::detail::pi_creation_rollback_barrier barrier{
        &observed, &rollback_observation::before_cleanup
    };
    const auto generated = config();
    const auto too_large = std::error_code{EFBIG, std::generic_category()}.message();
    bool restored = false;
    const int failed = [&]() -> int {
        scoped_lease_write_failure fault{restored};
        if (!fault.ready) {
            std::fprintf(stderr, "RLIMIT_FSIZE/SIGXFSZ lease-write fault unavailable\n");
        }
        REQUIRE(fault.ready);
        // The first regular-file write is the lease marker, after root ownership
        // and exclusive lease acquisition. It fails with EFBIG before children exist.
        auto denied = pi_private_state::create(f.directory, generated, barrier);
        REQUIRE(!denied);
        REQUIRE(denied.error().starts_with("write Pi private file: "));
        REQUIRE(denied.error().find(too_large) != std::string::npos);
        REQUIRE(observed.calls == 1);
        REQUIRE(observed.roots_before == 1);
        REQUIRE(observed.endpoint.revoked && observed.endpoint.joined);
        REQUIRE(observed.roots_after_join == 1);
        REQUIRE(count_run_roots(parent.get()) == 0);
        return 0;
    }();
    REQUIRE(restored);
    REQUIRE(failed == 0);
    REQUIRE(read(f.directory / "unrelated") == "sibling");
    REQUIRE(observed.calls == 1);
    return 0;
}

auto creation_barrier_not_retained() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    const std::unique_ptr<DIR, decltype(&::closedir)> parent{
        ::opendir(f.directory.c_str()), &::closedir
    };
    REQUIRE(parent != nullptr);
    rollback_observation observed{parent.get()};
    const glove::run::detail::pi_creation_rollback_barrier barrier{
        &observed, &rollback_observation::before_cleanup
    };
    auto oversized = config();
    oversized.models_json.assign(32767, 'x');
    oversized.settings_json.clear();
    REQUIRE(!pi_private_state::create(f.directory, oversized, barrier));
    REQUIRE(observed.calls == 0 && count_run_roots(parent.get()) == 0);
    REQUIRE(::chmod(f.directory.c_str(), 0750) == 0);
    auto unsafe = pi_private_state::create(f.directory, config(), barrier);
    REQUIRE(::chmod(f.directory.c_str(), 0700) == 0);
    REQUIRE(!unsafe);
    REQUIRE(observed.calls == 0 && count_run_roots(parent.get()) == 0);
    fs::path explicit_root;
    {
        auto state = pi_private_state::create(f.directory, config(), barrier);
        REQUIRE(state);
        explicit_root = state->root();
        REQUIRE(observed.calls == 0);
        REQUIRE(state->mark_launching());
        // Childless fixture only; no claim of actual process or kernel quiescence.
        REQUIRE(state->mark_quiescent());
        REQUIRE(state->cleanup());
        REQUIRE(!path_exists(explicit_root));
        REQUIRE(observed.calls == 0);
    }
    REQUIRE(observed.calls == 0);
    fs::path destructor_root;
    {
        auto state = pi_private_state::create(f.directory, config(), barrier);
        REQUIRE(state);
        destructor_root = state->root();
        REQUIRE(observed.calls == 0);
    }
    REQUIRE(!path_exists(destructor_root));
    REQUIRE(observed.calls == 0);
    REQUIRE(!observed.endpoint.revoked && !observed.endpoint.joined);
    REQUIRE(count_run_roots(parent.get()) == 0);
    return 0;
}

auto construction_and_cleanup() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    REQUIRE(write_fixture(f.directory / "unrelated", "sibling", 0600));
    auto first = pi_private_state::create(f.directory, config());
    if (!first) {
        std::fprintf(stderr, "private-state construction: %s\n", first.error().c_str());
    }
    REQUIRE(first);
    auto second = pi_private_state::create(f.directory, config());
    REQUIRE(second);
    REQUIRE(first->root() != second->root());
    const auto first_root = first->root();
    REQUIRE(first_root.parent_path() == f.directory);
    const auto name = first_root.filename().string();
    REQUIRE(name.size() == 52 && name.starts_with("run-"));
    REQUIRE(name.substr(4).find_first_not_of("0123456789abcdef") == std::string::npos);
    for (const auto& path :
         {first->root(), first->home(), first->tmp(), first->agent(), first->sessions()}) {
        REQUIRE(mode(path) == 0700);
    }
    REQUIRE(first->home().parent_path() == first->root());
    REQUIRE(first->tmp().parent_path() == first->root());
    REQUIRE(first->agent().parent_path() == first->root());
    REQUIRE(first->sessions().parent_path() == first->root());
    for (const auto& path : {first->models(), first->settings(), first->auth()}) {
        REQUIRE(path.parent_path() == first->agent());
        REQUIRE(mode(path) == 0400);
        struct stat info{};
        REQUIRE(::lstat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1);
    }
    REQUIRE(read(first->models()) == config().models_json);
    REQUIRE(read(first->settings()) == config().settings_json);
    REQUIRE(read(first->auth()) == "{}");
    REQUIRE(mode(first->root() / marker_name) == 0600);
    REQUIRE(read(first->root() / marker_name).ends_with("\nconstructing\n"));
    REQUIRE(!first->mark_quiescent());
    auto recovered = pi_private_state::recover(f.directory);
    REQUIRE(recovered && *recovered == 0); // Both same-process exclusive leases remain active.
    pi_private_state moved{std::move(*first)};
    REQUIRE(moved.cleanup());
    REQUIRE(moved.cleanup());
    REQUIRE(!path_exists(first_root));
    REQUIRE(path_exists(second->root()));
    REQUIRE(read(f.directory / "unrelated") == "sibling");
    const auto second_root = second->root();
    second = std::unexpected(std::string{"release constructing owner"});
    REQUIRE(!path_exists(second_root));
    return 0;
}

auto ordinary_guest_artifacts() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    auto state = pi_private_state::create(f.directory, config());
    REQUIRE(state);
    const auto root = state->root();
    REQUIRE(state->mark_launching());
    const auto cache = state->home() / ".cache";
    REQUIRE(::mkdir(cache.c_str(), 0755) == 0);
    REQUIRE(::chmod(cache.c_str(), 0755) == 0);
    REQUIRE(write_fixture(cache / "metadata.json", "fixture", 0644));
    REQUIRE(write_fixture(state->sessions() / "session.jsonl", "fixture", 0644));
    // No runtime is executed; simulate its default umask-generated artifacts
    // and the caller's successful owned-reap contract before cleanup.
    REQUIRE(state->mark_quiescent());
    REQUIRE(state->cleanup());
    REQUIRE(!path_exists(root));
    return 0;
}

#if defined(__APPLE__)
struct fixture_acl {
    acl_t value = ::acl_init(1);
    fixture_acl(const fixture_acl&) = delete;
    auto operator=(const fixture_acl&) -> fixture_acl& = delete;
    fixture_acl() = default;

    ~fixture_acl() {
        if (value != nullptr) {
            (void)::acl_free(value);
        }
    }
};

auto attach_fixture_acl(
    const fs::path& path, bool directory = true, acl_tag_t tag = ACL_EXTENDED_ALLOW
) -> bool {
    fixture_acl acl;
    acl_entry_t entry{};
    acl_permset_t permissions{};
    acl_flagset_t flags{};
    uuid_t principal{};
    // Known named-UID authority, not the test owner or an executed user.
    if (acl.value == nullptr || ::mbr_uid_to_uuid(65534, principal) != 0 ||
        ::acl_create_entry(&acl.value, &entry) != 0 || ::acl_set_tag_type(entry, tag) != 0 ||
        ::acl_set_qualifier(entry, principal) != 0 || ::acl_get_permset(entry, &permissions) != 0 ||
        ::acl_get_flagset_np(entry, &flags) != 0) {
        return false;
    }
    for (const auto permission :
         {ACL_READ_DATA,
          ACL_WRITE_DATA,
          ACL_APPEND_DATA,
          ACL_EXECUTE,
          ACL_DELETE,
          ACL_DELETE_CHILD,
          ACL_READ_ATTRIBUTES,
          ACL_WRITE_ATTRIBUTES,
          ACL_READ_EXTATTRIBUTES,
          ACL_WRITE_EXTATTRIBUTES,
          ACL_READ_SECURITY,
          ACL_WRITE_SECURITY}) {
        if (::acl_add_perm(permissions, permission) != 0) {
            return false;
        }
    }
    if (directory && (::acl_add_flag_np(flags, ACL_ENTRY_FILE_INHERIT) != 0 ||
                      ::acl_add_flag_np(flags, ACL_ENTRY_DIRECTORY_INHERIT) != 0)) {
        return false;
    }
    const int fd =
        ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0));
    if (fd < 0) {
        return false;
    }
    const bool attached = ::acl_set_fd_np(fd, acl.value, ACL_TYPE_EXTENDED) == 0;
    return ::close(fd) == 0 && attached;
}
#endif

auto acl_admission() -> int {
#if defined(__APPLE__)
    fixture f;
    REQUIRE(!f.directory.empty());
    REQUIRE(::geteuid() != 65534);
    REQUIRE(attach_fixture_acl(f.directory));
    REQUIRE(mode(f.directory) == 0700);
    // chmod's POSIX bits do not neutralize the named-UID allow/inherit ACE.
    auto denied = pi_private_state::create(f.directory, config());
    REQUIRE(!denied);
    REQUIRE(denied.error().find("ACL") != std::string::npos);
    REQUIRE(!pi_private_state::recover(f.directory));
    REQUIRE(fs::is_empty(f.directory));
    REQUIRE(!glove::detail::check_descriptor_acl(-1, glove::detail::acl_scope::owner_private));

    fixture lease;
    auto state = pi_private_state::create(lease.directory, config());
    REQUIRE(state);
    const auto retained = state->root();
    REQUIRE(attach_fixture_acl(retained / marker_name, false));
    REQUIRE(mode(retained / marker_name) == 0600);
    REQUIRE(!state->mark_launching());
    REQUIRE(!state->cleanup());
    REQUIRE(path_exists(retained));

    fixture artifact;
    auto completed = pi_private_state::create(artifact.directory, config());
    REQUIRE(completed && completed->mark_launching() && completed->mark_quiescent());
    const auto exposed = completed->tmp() / "artifact";
    REQUIRE(write_fixture(exposed, "fixture", 0644));
    REQUIRE(attach_fixture_acl(exposed, false));
    REQUIRE(!completed->cleanup());
    REQUIRE(mode(exposed) == 0644); // Refusal precedes even permission narrowing.
    REQUIRE(path_exists(completed->root() / marker_name));

    fixture restricted;
    REQUIRE(attach_fixture_acl(restricted.directory, true, ACL_EXTENDED_DENY));
    auto safe = pi_private_state::create(restricted.directory, config());
    REQUIRE(safe);
    const int root_fd = ::open(safe->root().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(root_fd >= 0);
    REQUIRE(glove::detail::check_descriptor_acl(root_fd, glove::detail::acl_scope::owner_private));
    REQUIRE(::close(root_fd) == 0);
    REQUIRE(safe->cleanup());
#endif
    return 0;
}

auto budget_and_parents() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    auto large = config();
    large.models_json.assign(32767, 'x');
    large.settings_json.clear();
    REQUIRE(!pi_private_state::create(f.directory, large));
    REQUIRE(fs::is_empty(f.directory));
    large.models_json.assign(32766, 'x');
    auto boundary = pi_private_state::create(f.directory, large);
    REQUIRE(boundary);
    REQUIRE(boundary->cleanup());
    REQUIRE(::chmod(f.directory.c_str(), 0750) == 0);
    REQUIRE(!pi_private_state::create(f.directory, config()));
    REQUIRE(!pi_private_state::recover(f.directory));
    REQUIRE(::chmod(f.directory.c_str(), 0700) == 0);
    REQUIRE(!pi_private_state::create(f.directory / ".", config()));
    REQUIRE(!pi_private_state::create(f.directory / ".." / f.directory.filename(), config()));
    REQUIRE(!pi_private_state::create(fs::path{f.directory.string() + "/"}, config()));
    REQUIRE(!pi_private_state::create("relative", config()));
    REQUIRE(!pi_private_state::create(f.directory / "missing", config()));
    const auto link = f.directory / "link";
    REQUIRE(::symlink(f.directory.c_str(), link.c_str()) == 0);
    REQUIRE(!pi_private_state::create(link, config()));
    const auto unsafe = f.directory / "unsafe";
    REQUIRE(::mkdir(unsafe.c_str(), 0770) == 0);
    REQUIRE(::chmod(unsafe.c_str(), 0770) == 0);
    REQUIRE(::mkdir((unsafe / "parent").c_str(), 0700) == 0);
    REQUIRE(!pi_private_state::create(unsafe / "parent", config()));
    return 0;
}

auto phases_and_retention() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    fs::path retained;
    {
        auto state = pi_private_state::create(f.directory, config());
        REQUIRE(state);
        retained = state->root();
        REQUIRE(state->mark_launching());
        REQUIRE(read(retained / marker_name).ends_with("\nlaunching\n"));
        REQUIRE(!state->mark_launching());
        REQUIRE(!state->cleanup());
        auto active = pi_private_state::recover(f.directory);
        REQUIRE(active && *active == 0);
        // No child is launched. Destruction releases only the host lease.
    }
    REQUIRE(path_exists(retained));
    auto launching = pi_private_state::recover(f.directory);
    REQUIRE(!launching);
    REQUIRE(launching.error().find("launching") != std::string::npos);
    REQUIRE(path_exists(retained));
    fixture g;
    REQUIRE(!g.directory.empty());
    fs::path removed;
    {
        auto state = pi_private_state::create(g.directory, config());
        REQUIRE(state);
        removed = state->root();
        REQUIRE(state->mark_launching());
        // Childless fixture stands in for the caller's owned-reap success contract.
        REQUIRE(state->mark_quiescent());
        REQUIRE(read(removed / marker_name).ends_with("\nquiescent\n"));
    }
    REQUIRE(!path_exists(removed));
    return 0;
}

auto recovery_cases() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    REQUIRE(write_fixture(f.directory / "sibling", "keep", 0600));
    const auto constructing = stale_fixture(f.directory, 'a', "constructing");
    const auto quiescent = stale_fixture(f.directory, 'b', "quiescent");
    REQUIRE(!constructing.empty() && !quiescent.empty());
    auto recovered = pi_private_state::recover(f.directory);
    REQUIRE(recovered && *recovered == 2);
    REQUIRE(!path_exists(constructing) && !path_exists(quiescent));
    REQUIRE(read(f.directory / "sibling") == "keep");
    const auto malformed = stale_fixture(f.directory, 'c', "unrecognized");
    REQUIRE(!malformed.empty());
    REQUIRE(!pi_private_state::recover(f.directory));
    REQUIRE(path_exists(malformed));
    fixture g;
    REQUIRE(!g.directory.empty());
    const auto root = stale_fixture(g.directory, 'd', "constructing");
    REQUIRE(!root.empty());
    REQUIRE(::link((root / marker_name).c_str(), (g.directory / "alias").c_str()) == 0);
    REQUIRE(!pi_private_state::recover(g.directory));
    REQUIRE(path_exists(root));
    REQUIRE(::unlink((g.directory / "alias").c_str()) == 0);
    REQUIRE(::unlink((root / marker_name).c_str()) == 0);
    REQUIRE(::symlink((g.directory / "target").c_str(), (root / marker_name).c_str()) == 0);
    REQUIRE(!pi_private_state::recover(g.directory));
    REQUIRE(path_exists(root));
    fixture h;
    REQUIRE(!h.directory.empty());
    const auto name = h.directory / ("run-" + std::string(48, 'e'));
    REQUIRE(::symlink(f.directory.c_str(), name.c_str()) == 0);
    REQUIRE(!pi_private_state::recover(h.directory));
    REQUIRE(path_exists(name));
    REQUIRE(::unlink(name.c_str()) == 0);
    REQUIRE(::mkdir((h.directory / "run-bad").c_str(), 0700) == 0);
    REQUIRE(!pi_private_state::recover(h.directory));
    fixture unbound;
    REQUIRE(!unbound.directory.empty());
    const auto unbound_root = stale_fixture(unbound.directory, 'f', "constructing");
    REQUIRE(!unbound_root.empty());
    const auto bytes = read(unbound_root / marker_name);
    REQUIRE(::unlink((unbound_root / marker_name).c_str()) == 0);
    REQUIRE(write_fixture(unbound_root / marker_name, bytes + "extra", 0600));
    REQUIRE(!pi_private_state::recover(unbound.directory));
    REQUIRE(path_exists(unbound_root));
    REQUIRE(::unlink((unbound_root / marker_name).c_str()) == 0);
    REQUIRE(
        write_fixture(unbound_root / marker_name, "glove-pi-private-v1\n0\n0\nconstructing\n", 0600)
    );
    REQUIRE(!pi_private_state::recover(unbound.directory));
    REQUIRE(path_exists(unbound_root));
    fixture unsafe;
    REQUIRE(!unsafe.directory.empty());
    const auto unsafe_root = stale_fixture(unsafe.directory, 'a', "quiescent");
    REQUIRE(!unsafe_root.empty());
    REQUIRE(::chmod(unsafe_root.c_str(), 0755) == 0);
    REQUIRE(!pi_private_state::recover(unsafe.directory));
    REQUIRE(path_exists(unsafe_root));
    REQUIRE(::chmod(unsafe_root.c_str(), 0700) == 0);
    REQUIRE(
        ::symlink((unsafe.directory / "outside").c_str(), (unsafe_root / "symlink").c_str()) == 0
    );
    REQUIRE(!pi_private_state::recover(unsafe.directory));
    REQUIRE(path_exists(unsafe_root / marker_name));
    return 0;
}

auto drift_and_cleanup_errors() -> int {
    fixture f;
    REQUIRE(!f.directory.empty());
    auto state = pi_private_state::create(f.directory, config());
    REQUIRE(state);
    const auto original = state->root();
    const auto moved = f.directory / "detached";
    REQUIRE(::rename(original.c_str(), moved.c_str()) == 0);
    REQUIRE(::mkdir(original.c_str(), 0700) == 0);
    REQUIRE(write_fixture(original / "replacement", "do not delete", 0600));
    REQUIRE(!state->cleanup());
    REQUIRE(path_exists(moved));
    REQUIRE(read(original / "replacement") == "do not delete");
    REQUIRE(!state->mark_launching());
    fixture g;
    REQUIRE(!g.directory.empty());
    auto aliased = pi_private_state::create(g.directory, config());
    REQUIRE(aliased);
    REQUIRE(::link(aliased->models().c_str(), (g.directory / "config-alias").c_str()) == 0);
    const auto retained = aliased->root();
    auto cleaned = aliased->cleanup();
    REQUIRE(!cleaned);
    REQUIRE(path_exists(retained));
    REQUIRE(read(g.directory / "config-alias") == config().models_json);
    fixture h;
    REQUIRE(!h.directory.empty());
    auto changed = pi_private_state::create(h.directory, config());
    REQUIRE(changed);
    const auto changed_root = changed->root();
    REQUIRE(::chmod(h.directory.c_str(), 0755) == 0);
    REQUIRE(!changed->cleanup());
    REQUIRE(path_exists(changed_root));
    REQUIRE(::chmod(h.directory.c_str(), 0700) == 0);
    fixture lease;
    REQUIRE(!lease.directory.empty());
    auto replaced = pi_private_state::create(lease.directory, config());
    REQUIRE(replaced);
    const auto lease_path = replaced->root() / marker_name;
    const auto bytes = read(lease_path);
    REQUIRE(::rename(lease_path.c_str(), (lease.directory / "old-lease").c_str()) == 0);
    REQUIRE(write_fixture(lease_path, bytes, 0600));
    REQUIRE(!replaced->mark_launching());
    REQUIRE(!replaced->cleanup());
    REQUIRE(path_exists(replaced->root()));
    fixture parent;
    REQUIRE(!parent.directory.empty());
    const auto container = parent.directory / "parent";
    REQUIRE(::mkdir(container.c_str(), 0700) == 0);
    auto detached = pi_private_state::create(container, config());
    REQUIRE(detached);
    const auto detached_name = detached->root().filename();
    REQUIRE(::rename(container.c_str(), (parent.directory / "old-parent").c_str()) == 0);
    REQUIRE(::mkdir(container.c_str(), 0700) == 0);
    REQUIRE(!detached->cleanup());
    REQUIRE(path_exists(parent.directory / "old-parent" / detached_name));
    REQUIRE(fs::is_empty(container));
    return 0;
}

} // namespace

auto main() -> int {
    for (const auto test :
         {signal_restoration_contract,
          creation_rollback_barrier,
          creation_barrier_not_retained,
          construction_and_cleanup,
          ordinary_guest_artifacts,
          acl_admission,
          budget_and_parents,
          phases_and_retention,
          recovery_cases,
          drift_and_cleanup_errors}) {
        if (const int failed = test(); failed != 0) {
            return failed;
        }
    }
    return 0;
}
