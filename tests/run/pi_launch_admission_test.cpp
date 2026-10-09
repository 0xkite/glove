#include "glove/host/config.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/run/pi_launch.hpp"
#include "glove/run/pi_runtime.hpp"

#include "../support/descriptor_acl_fixture.hpp"
#include "pi_launch_internal.hpp"
#include "pi_runtime_internal.hpp"

#if defined(__APPLE__)
#    include "pi_admission_environment.hpp"
#endif

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using launch_result = std::expected<int, std::string>;
using glove::run::detail::launch_pi_with_context;
using glove::run::detail::pi_launch_context;

#if defined(__APPLE__)
constexpr std::string_view catalog_suffix =
    "node_modules/@earendil-works/pi-ai/dist/providers/data";
// Exact copied catalog identities, not evidence of live model availability.
constexpr std::string_view openai_catalog =
    R"({"openai-responses":{"chat:gpt-5":{"id":"gpt-5","provider":"openai","api":"openai-responses","type":"chat"}}})";
constexpr std::string_view anthropic_catalog =
    R"({"anthropic-messages":{"chat:claude-sonnet-4-6":{"id":"claude-sonnet-4-6","provider":"anthropic","api":"anthropic-messages","type":"chat"}}})";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-pi-admission-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = fs::canonical(created);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        // Only this fixture's names are removed, never operator state or a sweep.
        std::error_code ignored;
        if (!root_.empty() && !retained_) {
            for (const auto& entry : fs::recursive_directory_iterator(root_, ignored)) {
                if (fs::is_directory(entry.symlink_status(ignored))) {
                    fs::permissions(
                        entry.path(), fs::perms::owner_write, fs::perm_options::add, ignored
                    );
                }
            }
            fs::remove_all(root_, ignored);
        }
    }

    auto root() const -> const fs::path& { return root_; }

    void retain() noexcept { retained_ = true; }

private:
    fs::path root_;
    bool retained_ = false;
};

using glove::run::admission_test_support::contents;
using glove::run::admission_test_support::environment_entries;
using glove::run::admission_test_support::environment_scope;
using glove::run::admission_test_support::private_directory;
using glove::run::admission_test_support::public_fixture;
using glove::run::admission_test_support::write_file;

auto absent(const fs::path& path) -> bool {
    struct stat info{};
    return ::lstat(path.c_str(), &info) < 0 && errno == ENOENT;
}

auto stage_record(const fs::path& root, const glove::host::directories& dirs) -> int {
    const auto source = root / "source";
    const auto package = source / "lib/node_modules/@fixture/pi";
    for (const auto& path :
         {root,
          dirs.config / "pi",
          dirs.data / "pi",
          source / "bin",
          package / "bin",
          package / catalog_suffix}) {
        REQUIRE(private_directory(path));
    }
    REQUIRE(write_file(source / "bin/node", "#!/bin/sh\nexit 0\n", 0700));
    REQUIRE(write_file(package / "bin/pi", "#!/usr/bin/env node\n", 0700));
    REQUIRE(write_file(package / "package.json", "{}\n"));
    REQUIRE(write_file(package / catalog_suffix / "openai.json", openai_catalog));
    REQUIRE(write_file(package / catalog_suffix / "anthropic.json", anthropic_catalog));
    fs::create_symlink(fs::relative(package / "bin/pi", source / "bin"), source / "bin/pi");
    REQUIRE(::chmod(source.c_str(), 0770) == 0);
    // Script-only closure: neither dependency tools nor these scripts execute.
    auto staged = glove::host::stage_runtime_harness(
        {.runtime_id = "pi",
         .source_executable = source / "bin/pi",
         .protected_directory = dirs.data / "pi/runtime",
         .dry_run = false}
    );
    REQUIRE(staged && !staged->snapshot_digest.empty() && staged->launch_arguments.size() == 1);
    glove::run::pi_runtime_selection saved{
        .model = {.provider = glove::run::pi_provider::openai, .model = "gpt-5"}, .runtime = *staged
    };
    auto stored =
        glove::run::store_pi_runtime_selection(dirs.config / "pi/selection.json", saved, true);
    REQUIRE(stored && *stored);
    const auto copied = fs::path{staged->launch_arguments.front()}.parent_path().parent_path();
    REQUIRE(contents(copied / catalog_suffix / "openai.json") == openai_catalog);
    REQUIRE(contents(copied / catalog_suffix / "anthropic.json") == anthropic_catalog);
    return 0;
}

class synthetic_endpoint final : public glove::net::credentialed_endpoint {
public:
    explicit synthetic_endpoint(std::string nonce) : nonce_{std::move(nonce)} {}

    auto port() const -> std::uint16_t override { return 32123; }

    auto base_url(glove::net::endpoint_provider provider) const
        -> std::expected<std::string, std::string> override {
        if (provider != glove::net::endpoint_provider::openai) {
            return std::unexpected("wrong synthetic provider");
        }
        return "http://127.0.0.1:32123/openai";
    }

    auto session_nonce(glove::net::endpoint_provider provider) const
        -> std::expected<std::string, std::string> override {
        if (provider != glove::net::endpoint_provider::openai) {
            return std::unexpected("wrong synthetic provider");
        }
        return nonce_;
    }

private:
    std::string nonce_;
};

class stdio_scope {
public:
    stdio_scope() {
        // Capture every original mapping before closing any selected slot.
        for (int slot = 0; slot != 3; ++slot) {
            auto& entry = entries_[static_cast<std::size_t>(slot)];
            entry.flags = ::fcntl(slot, F_GETFD);
            if (entry.flags < 0) {
                ready_ = false;
                continue;
            }
            entry.status = ::fcntl(slot, F_GETFL);
            entry.backup = ::fcntl(slot, F_DUPFD_CLOEXEC, 3);
            ready_ = entry.backup >= 3 && entry.status >= 0 &&
                     ::fstat(slot, &entry.identity) == 0 && ready_;
        }
    }

    stdio_scope(const stdio_scope&) = delete;
    auto operator=(const stdio_scope&) -> stdio_scope& = delete;

    ~stdio_scope() { (void)restore(); }

    auto ready() const -> bool { return ready_; }

    auto close_mask(unsigned int mask) -> bool {
        if (!ready_) {
            return false;
        }
        bool ok = true;
        for (int slot = 0; slot != 3; ++slot) {
            if ((mask & (1U << static_cast<unsigned int>(slot))) != 0) {
                ok = (::close(slot) == 0) && ok;
            }
        }
        return ok;
    }

    auto restore() noexcept -> bool {
        if (restored_) {
            return restore_ok_;
        }
        restored_ = true;
        for (int slot = 0; slot != 3; ++slot) {
            auto& entry = entries_[static_cast<std::size_t>(slot)];
            if (entry.backup < 0) {
                continue;
            }
            const bool mapped =
                ::dup2(entry.backup, slot) == slot && ::fcntl(slot, F_SETFD, entry.flags) == 0;
            struct stat now{};
            const bool checked =
                mapped && ::fstat(slot, &now) == 0 && now.st_dev == entry.identity.st_dev &&
                now.st_ino == entry.identity.st_ino && now.st_rdev == entry.identity.st_rdev &&
                now.st_mode == entry.identity.st_mode && ::fcntl(slot, F_GETFD) == entry.flags &&
                ::fcntl(slot, F_GETFL) == entry.status;
            const bool closed = ::close(entry.backup) == 0;
            restore_ok_ = checked && closed && restore_ok_;
            entry.backup = -1;
        }
        return restore_ok_;
    }

private:
    struct entry {
        int backup = -1;
        int flags = -1;
        int status = -1;
        struct stat identity{};
    };

    std::array<entry, 3> entries_{};
    bool ready_ = true;
    bool restored_ = false;
    bool restore_ok_ = true;
};

auto closed_stdio_case(const fs::path& root, unsigned int mask) -> int {
    pi_launch_context context;
    context.directories = {
        root / "config", root / "state", root / "data", root / "cache", root / "runtime"
    };
    for (const auto& path :
         {root,
          root / "workspace",
          context.directories.config,
          context.directories.state,
          context.directories.data,
          context.directories.cache,
          context.directories.runtime}) {
        REQUIRE(private_directory(path));
    }
    REQUIRE(stage_record(root, context.directories) == 0);
    const auto runs = context.directories.runtime / "pi/runs";
    REQUIRE(absent(runs));
    int credentials = 0;
    int endpoints = 0;
    int executions = 0;
    context.credential = [&](glove::run::pi_provider) -> std::expected<std::string, std::string> {
        ++credentials;
        return "synthetic-host-key-never-print";
    };
    context.start_endpoint = [&](glove::net::credentialed_endpoint_options options)
        -> std::expected<std::unique_ptr<glove::net::credentialed_endpoint>, std::string> {
        ++endpoints;
        if (options.endpoints.size() != 1) {
            return std::unexpected("bad synthetic endpoint binding");
        }
        return std::make_unique<synthetic_endpoint>(options.endpoints.front().session_nonce);
    };
    // No process, group, socket or thread exists here. Success models only the
    // owned API contract and must never be reported as observed guest death.
    context.execute_owned = [&](const glove::container::profile&,
                                const std::vector<std::string>&,
                                std::stop_token) -> launch_result {
        ++executions;
        return 7;
    };
    const glove::run::pi_launch_request request{.selection = {}, .workspace = root / "workspace"};
    std::optional<launch_result> result;
    bool closed = false;
    bool restored = false;
    bool threw = false;
    {
        stdio_scope stdio;
        REQUIRE(stdio.ready());
        closed = stdio.close_mask(mask);
        try {
            if (closed) {
                result.emplace(launch_pi_with_context(request, context));
            }
        } catch (...) {
            threw = true;
        }
        restored = stdio.restore();
    }
    // All mappings and the result are back in the parent before diagnostics.
    REQUIRE(restored && closed && !threw && result);
    REQUIRE(!*result);
    REQUIRE(credentials == 0 && endpoints == 0 && executions == 0);
    REQUIRE(absent(runs));
    return 0;
}

auto metadata(const fs::path& path) -> std::optional<struct stat> {
    struct stat info{};
    if (::lstat(path.c_str(), &info) != 0) {
        return std::nullopt;
    }
    return info;
}

auto preserved(const fs::path& path, const struct stat& before) -> bool {
    const auto now = metadata(path);
    return now && now->st_dev == before.st_dev && now->st_ino == before.st_ino &&
           now->st_uid == before.st_uid && now->st_gid == before.st_gid &&
           now->st_mode == before.st_mode && now->st_nlink == before.st_nlink &&
           now->st_size == before.st_size &&
           now->st_mtimespec.tv_sec == before.st_mtimespec.tv_sec &&
           now->st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec &&
           now->st_ctimespec.tv_sec == before.st_ctimespec.tv_sec &&
           now->st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec;
}

auto unsafe_config(const launch_result& result) -> bool {
    // A static diagnostic category distinguishes public admission from the
    // later missing-runtime refusal. Never infer authority or quiescence here.
    return !result && result.error().starts_with("unsafe host control configuration:");
}

auto public_closed_stdio_case(const fs::path& root, unsigned int mask) -> int {
    public_fixture f{.root = root, .dirs = {}, .environment = {}};
    REQUIRE(f.prepare() == 0);
    // Unsafe configuration must lose to stdio admission: checking only in the
    // private entry would allow the public reader to open it first.
    REQUIRE(::chmod(f.config_path().c_str(), 0644) == 0);
    const auto before = metadata(f.config_path());
    REQUIRE(before);
    std::optional<launch_result> result;
    bool closed = false;
    bool restored = false;
    bool threw = false;
    {
        stdio_scope stdio;
        REQUIRE(stdio.ready());
        closed = stdio.close_mask(mask);
        try {
            if (closed) {
                result.emplace(f.launch());
            }
        } catch (...) {
            threw = true;
        }
        restored = stdio.restore();
    }
    REQUIRE(restored && closed && !threw && result && !*result);
    REQUIRE(result->error() == "stdio must be open before launch preparation");
    REQUIRE(preserved(f.config_path(), *before));
    REQUIRE(absent(f.dirs.runtime / "pi/runs"));
    return 0;
}

enum class config_case {
    missing,
    valid,
    leaf_mode,
    allow_write,
    allow_read,
    deny,
    writable_ancestor,
    acl_ancestor,
    symlink_ancestor,
    malformed,
    empty,
    hardlink,
    leaf_symlink,
    byte_limit,
    oversized
};

auto public_config_case(const fs::path& root, config_case selected) -> int {
    public_fixture f{.root = root, .dirs = {}, .environment = {}};
    REQUIRE(f.prepare() == 0);
    const auto path = f.config_path();
    const auto ancestor = root / "xdg-config";
    if (selected == config_case::missing) {
        REQUIRE(::unlink(path.c_str()) == 0);
    } else if (selected == config_case::leaf_mode) {
        REQUIRE(::chmod(path.c_str(), 0644) == 0);
    } else if (
        selected == config_case::allow_write || selected == config_case::allow_read ||
        selected == config_case::deny
    ) {
        REQUIRE(
            glove::test::set_fixture_acl(
                path,
                false,
                selected == config_case::deny ? ACL_EXTENDED_DENY : ACL_EXTENDED_ALLOW,
                selected == config_case::allow_read
            )
        );
    } else if (selected == config_case::writable_ancestor) {
        REQUIRE(::chmod(ancestor.c_str(), 0770) == 0);
    } else if (selected == config_case::acl_ancestor) {
        REQUIRE(glove::test::set_fixture_acl(ancestor, true));
    } else if (selected == config_case::symlink_ancestor) {
        fs::rename(ancestor, root / "real-config");
        fs::create_symlink(root / "real-config", ancestor);
    } else if (selected == config_case::malformed || selected == config_case::empty) {
        REQUIRE(write_file(path, selected == config_case::empty ? "" : "{"));
    } else if (selected == config_case::hardlink) {
        fs::create_hard_link(path, root / "config-peer");
    } else if (selected == config_case::leaf_symlink) {
        fs::rename(path, root / "config-target");
        fs::create_symlink(root / "config-target", path);
    } else if (selected == config_case::byte_limit || selected == config_case::oversized) {
        auto padded = contents(path);
        constexpr std::size_t limit = 1024U * 1024U;
        REQUIRE(padded.size() < limit);
        padded.resize(limit + (selected == config_case::oversized ? 1U : 0U), ' ');
        REQUIRE(write_file(path, padded));
    }
    const auto before_leaf = metadata(path);
    const auto before_parent = metadata(path.parent_path());
    const auto before_ancestor = metadata(ancestor);
    REQUIRE(before_parent && before_ancestor);
    const auto bytes = before_leaf ? contents(path) : std::string{};
    const auto result = f.launch(); // Environment restoration precedes assertions.
    REQUIRE(preserved(path.parent_path(), *before_parent));
    REQUIRE(preserved(ancestor, *before_ancestor));
    if (before_leaf) {
        REQUIRE(preserved(path, *before_leaf) && contents(path) == bytes);
    } else {
        REQUIRE(absent(path));
    }
    REQUIRE(absent(f.dirs.runtime / "pi/runs"));
    REQUIRE(absent(f.dirs.config / "pi/selection.json"));
    if (selected == config_case::missing || selected == config_case::valid ||
        selected == config_case::deny || selected == config_case::byte_limit) {
        REQUIRE(!result && result.error().starts_with("Pi runtime is not configured;"));
    } else {
        REQUIRE(unsafe_config(result));
    }
    return 0;
}

auto operator_file_depth_case(const fs::path& root) -> int {
    REQUIRE(private_directory(root));
    auto parent = root;
    while (std::distance(parent.begin(), parent.end()) < 127) {
        parent /= "d";
    }
    REQUIRE(private_directory(parent));
    const auto admitted_path = parent / "control.json";
    REQUIRE(std::distance(admitted_path.begin(), admitted_path.end()) == 128);
    REQUIRE(write_file(admitted_path, "operator-depth-boundary"));
    const auto before = metadata(admitted_path);
    REQUIRE(before);
    const auto admitted = glove::run::detail::read_pi_operator_file(admitted_path);
    REQUIRE(admitted && *admitted && **admitted == "operator-depth-boundary");
    REQUIRE(preserved(admitted_path, *before));
    REQUIRE(private_directory(parent / "d"));
    const auto rejected_path = parent / "d/control.json";
    REQUIRE(std::distance(rejected_path.begin(), rejected_path.end()) == 129);
    REQUIRE(write_file(rejected_path, "operator-depth-rejected"));
    const auto rejected_before = metadata(rejected_path);
    REQUIRE(rejected_before);
    REQUIRE(!glove::run::detail::read_pi_operator_file(rejected_path));
    REQUIRE(preserved(rejected_path, *rejected_before));
    REQUIRE(contents(rejected_path) == "operator-depth-rejected");
    return 0;
}

auto external_authority_case(const fs::path& root) -> int {
    public_fixture f{.root = root, .dirs = {}, .environment = {}};
    REQUIRE(f.prepare() == 0);
    REQUIRE(stage_record(root / "synthetic", f.dirs) == 0);
    const auto key = root / "external/keys/audit.key";
    REQUIRE(write_file(key, "synthetic audit authority, not a provider credential"));
    const auto before = metadata(key);
    REQUIRE(before);
    const auto bytes = contents(key);
    auto request = f.request();
    request.workspace = key.parent_path();
    std::optional<launch_result> result;
    bool restored = false;
    {
        environment_scope scoped{f.environment};
        REQUIRE(scoped.ok());
        result.emplace(glove::run::launch_pi(request));
        restored = scoped.restore();
    }
    REQUIRE(restored && result && !*result);
    REQUIRE(
        result->error().starts_with("Pi workspace overlaps protected host or runtime authority")
    );
    REQUIRE(preserved(key, *before) && contents(key) == bytes);
    REQUIRE(absent(f.dirs.runtime / "pi/runs"));
    return 0;
}

// This fresh self-exec is the only real child. It never executes Pi/Node or
// starts a listener. Do not disable sanitizer lanes. Recommend CTest TIMEOUT
// 60s: the FIFO probe has its own 5s deadline plus 2s kill/reap grace; the outer
// timeout is infrastructure containment, not admission evidence.
class spawn_configuration {
public:
    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};
    spawn_configuration() = default;
    spawn_configuration(const spawn_configuration&) = delete;
    auto operator=(const spawn_configuration&) -> spawn_configuration& = delete;

    ~spawn_configuration() { (void)close(); }

    auto initialize() -> bool {
        actions_owned_ = ::posix_spawn_file_actions_init(&actions) == 0;
        if (!actions_owned_) {
            return false;
        }
        attributes_owned_ = ::posix_spawnattr_init(&attributes) == 0;
        return attributes_owned_;
    }

    auto close() noexcept -> bool {
        bool ok = true;
        if (attributes_owned_) {
            attributes_owned_ = false;
            ok = ::posix_spawnattr_destroy(&attributes) == 0;
        }
        if (actions_owned_) {
            actions_owned_ = false;
            const bool destroyed = ::posix_spawn_file_actions_destroy(&actions) == 0;
            ok = destroyed && ok;
        }
        return ok;
    }

private:
    bool actions_owned_ = false;
    bool attributes_owned_ = false;
};

class probe_owner {
public:
    pid_t pid = -1;
    bool reaped = false;
    bool ownership_known = true;

    explicit probe_owner(bool& uncertain_child) noexcept : uncertain_child_{uncertain_child} {}

    probe_owner(const probe_owner&) = delete;
    auto operator=(const probe_owner&) -> probe_owner& = delete;

    ~probe_owner() {
        if (pid > 0 && !reaped) {
            uncertain_child_ = !cleanup();
        }
    }

    auto cleanup() -> bool {
        if (pid <= 0 || reaped) {
            return true;
        }
        if (!ownership_known) {
            return false;
        }
        if (!cleanup_deadline_) {
            cleanup_deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        }
        if (std::chrono::steady_clock::now() >= *cleanup_deadline_) {
            return false;
        }
        // Fence the signal with unreaped-child ownership. Unexpected inspection
        // results, including ECHILD, revoke PGID authority rather than retry it.
        siginfo_t observed{};
        bool inspected = false;
        for (int attempt = 0; attempt != 8; ++attempt) {
            if (::waitid(P_PID, static_cast<id_t>(pid), &observed, WEXITED | WNOHANG | WNOWAIT) ==
                0) {
                inspected = observed.si_pid == 0 || observed.si_pid == pid;
                break;
            }
            if (errno != EINTR) {
                break;
            }
        }
        if (!inspected) {
            ownership_known = false;
            return false;
        }
        // The self-probe creates no descendants. This is not a general group-
        // death assertion, and excludes a competing reaper in this fixture.
        const bool signalled = ::kill(-pid, SIGKILL) == 0 || errno == ESRCH;
        do {
            int status = 0;
            const auto waited = ::waitpid(pid, &status, WNOHANG);
            if (waited == pid) {
                reaped = true;
                return signalled;
            }
            if (waited < 0 && errno != EINTR) {
                ownership_known = false;
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        } while (std::chrono::steady_clock::now() < *cleanup_deadline_);
        return false;
    }

private:
    bool& uncertain_child_;
    std::optional<std::chrono::steady_clock::time_point> cleanup_deadline_;
};

auto fifo_probe() -> int {
    if (::getpgrp() != ::getpid()) {
        return 90;
    }
    for (int slot = 0; slot != 3; ++slot) {
        struct stat info{};
        const int flags = ::fcntl(slot, F_GETFL);
        if (::fstat(slot, &info) != 0 || !S_ISCHR(info.st_mode) || flags < 0 ||
            (flags & O_ACCMODE) != (slot == 0 ? O_RDONLY : O_WRONLY)) {
            return 91;
        }
    }
    const auto result = glove::run::launch_pi({.selection = {}, .workspace = std::nullopt});
    return unsafe_config(result) ? 0 : 92;
}

auto fifo_case(const fs::path& root, const fs::path& self, bool& uncertain_child) -> int {
    public_fixture f{.root = root, .dirs = {}, .environment = {}};
    REQUIRE(f.prepare() == 0);
    REQUIRE(::unlink(f.config_path().c_str()) == 0);
    REQUIRE(::mkfifo(f.config_path().c_str(), 0600) == 0);
    REQUIRE(::chmod(f.config_path().c_str(), 0600) == 0);
    const auto before = metadata(f.config_path());
    REQUIRE(before && S_ISFIFO(before->st_mode));
    const auto executable = metadata(self);
    REQUIRE(executable && S_ISREG(executable->st_mode) && ::access(self.c_str(), X_OK) == 0);
    std::vector<std::string> env;
    for (const auto& [name, value] : f.environment) {
        if (value) {
            env.push_back(name + "=" + *value);
        }
    }
    std::vector<char*> envp;
    for (auto& entry : env) {
        envp.push_back(entry.data());
    }
    envp.push_back(nullptr); // No ambient provider keys, PATH, or operator home.
    std::string executable_path = self.string();
    std::string mode = "--pi-admission-fifo-probe";
    std::array<char*, 3> argv{executable_path.data(), mode.data(), nullptr};
    spawn_configuration setup;
    REQUIRE(setup.initialize());
    bool configured = ::posix_spawnattr_setflags(
                          &setup.attributes, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT
                      ) == 0 &&
                      ::posix_spawnattr_setpgroup(&setup.attributes, 0) == 0;
    for (int slot = 0; slot != 3; ++slot) {
        configured = (::posix_spawn_file_actions_addopen(
                          &setup.actions, slot, "/dev/null", slot == 0 ? O_RDONLY : O_WRONLY, 0
                      ) == 0) &&
                     configured;
    }
    probe_owner child{uncertain_child};
    pid_t spawned_pid = -1;
    const int spawned = configured ? ::posix_spawn(
                                         &spawned_pid,
                                         self.c_str(),
                                         &setup.actions,
                                         &setup.attributes,
                                         argv.data(),
                                         envp.data()
                                     )
                                   : EINVAL;
    if (spawned == 0 && spawned_pid > 0) {
        child.pid = spawned_pid;
        uncertain_child = true;
    }
    const bool destroyed = setup.close();
    REQUIRE(configured && spawned == 0 && destroyed && child.pid > 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    int status = 0;
    bool wait_ok = true;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto waited = ::waitpid(child.pid, &status, WNOHANG);
        if (waited == child.pid) {
            child.reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            child.ownership_known = false;
            wait_ok = false;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    const bool timed_out = !child.reaped;
    const bool cleaned = child.cleanup(); // Kill/reap the original group before REQUIRE.
    uncertain_child = !cleaned;
    REQUIRE(cleaned);
    REQUIRE(preserved(f.config_path(), *before)); // Never read the FIFO in the parent.
    REQUIRE(absent(f.dirs.runtime / "pi/runs"));
    REQUIRE(wait_ok && !timed_out); // Current blocking open is a bounded behavioral red.
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
#endif

} // namespace

auto main(int argc, char* argv[]) -> int {
#if defined(__APPLE__)
    if (argc == 2 && std::string_view{argv[1]} == "--pi-admission-fifo-probe") {
        return fifo_probe();
    }
    REQUIRE(argc == 1);
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    std::error_code error;
    const auto self = fs::canonical(argv[0], error);
    REQUIRE(!error);
    int failures = 0;
    // Continue through independent cases so the first red cannot hide the FIFO
    // deadline or another closed-stdio mask. No REQUIRE while slots are closed.
    for (unsigned int mask = 1; mask != 8; ++mask) {
        failures += closed_stdio_case(temporary.root() / ("stdio-" + std::to_string(mask)), mask);
        failures += public_closed_stdio_case(
            temporary.root() / ("public-stdio-" + std::to_string(mask)), mask
        );
    }
    for (const auto selected :
         {config_case::missing,
          config_case::valid,
          config_case::leaf_mode,
          config_case::allow_write,
          config_case::allow_read,
          config_case::deny,
          config_case::writable_ancestor,
          config_case::acl_ancestor,
          config_case::symlink_ancestor,
          config_case::malformed,
          config_case::empty,
          config_case::hardlink,
          config_case::leaf_symlink,
          config_case::byte_limit,
          config_case::oversized}) {
        failures += public_config_case(
            temporary.root() / ("config-" + std::to_string(static_cast<int>(selected))), selected
        );
    }
    failures += operator_file_depth_case(temporary.root() / "operator-depth");
    failures += external_authority_case(temporary.root() / "external-authority");
    bool uncertain_child = false;
    failures += fifo_case(temporary.root() / "fifo", self, uncertain_child);
    if (uncertain_child) {
        temporary.retain();
    }
    return failures == 0 ? 0 : 1;
#else
    (void)argc;
    (void)argv;
    return 77; // Native Pi admission is Darwin-only, not a sanitizer exclusion.
#endif
}
