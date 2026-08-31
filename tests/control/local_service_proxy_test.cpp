#include "glove/audit/sink.hpp"
#include "glove/container/digest.hpp"
#include "glove/container/receipt_producer.hpp"
#include "glove/control/guest_channel_transport.hpp"
#include "glove/control/local_service_proxy.hpp"
#include "glove/control/receipt_audit_protocol.hpp"
#include "glove/control/session_registry.hpp"
#include "glove/supervisor/path_alias.hpp"
#include "glove/supervisor/session_plan.hpp"

#include "adapters/sage/guest_channel.hpp"
#include "cgroup_v2.hpp"
#include "linux_session_executor.hpp"
#include "linux_session_preparation.hpp"

#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#    define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef MNT_DETACH
#    define MNT_DETACH 2
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(__has_feature)
#    if __has_feature(thread_sanitizer)
#        define GLOVE_LOCAL_PROXY_TSAN 1
#    endif
#endif
#ifndef GLOVE_LOCAL_PROXY_TSAN
#    define GLOVE_LOCAL_PROXY_TSAN 0
#endif

namespace allocation_fault {
std::atomic<std::int64_t> remaining{-1};
}

#if !GLOVE_LOCAL_PROXY_TSAN
void* operator new(std::size_t size) {
    const auto before = allocation_fault::remaining.load();
    if (before == 0) {
        allocation_fault::remaining.store(-1);
        throw std::bad_alloc{};
    }
    if (before > 0) {
        allocation_fault::remaining.fetch_sub(1);
    }
    if (void* allocation = std::malloc(size); allocation != nullptr) {
        return allocation;
    }
    throw std::bad_alloc{};
}

void operator delete(void* allocation) noexcept {
    std::free(allocation);
}

void operator delete(void* allocation, [[maybe_unused]] std::size_t size) noexcept {
    std::free(allocation);
}
#endif

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            if (descriptor_ >= 0) {
                static_cast<void>(::close(descriptor_));
            }
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-local-service-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

class rejecting_sink final : public glove::audit::sink {
public:
    auto record(const glove::audit::event&) -> std::expected<void, std::string> override {
        return std::unexpected(std::string{"audit unavailable"});
    }
};

class fail_terminal_sink final : public glove::audit::sink {
public:
    auto record(const glove::audit::event& event) -> std::expected<void, std::string> override {
        const std::scoped_lock lock{mutex_};
        if (!events_.empty()) {
            return std::unexpected(std::string{"terminal audit unavailable"});
        }
        events_.push_back(event);
        return {};
    }

    auto take() -> std::vector<glove::audit::event> {
        const std::scoped_lock lock{mutex_};
        return events_;
    }

private:
    std::mutex mutex_;
    std::vector<glove::audit::event> events_;
};

class delayed_sink final : public glove::audit::sink {
public:
    explicit delayed_sink(std::chrono::milliseconds delay) : delay_{delay} {}

    auto record(const glove::audit::event& event) -> std::expected<void, std::string> override {
        {
            const std::scoped_lock lock{mutex_};
            events_.push_back(event);
        }
        std::this_thread::sleep_for(delay_);
        return {};
    }

    auto take() -> std::vector<glove::audit::event> {
        const std::scoped_lock lock{mutex_};
        return events_;
    }

private:
    std::chrono::milliseconds delay_;
    std::mutex mutex_;
    std::vector<glove::audit::event> events_;
};

auto make_owner_directory(const std::filesystem::path& path) -> bool {
    return std::filesystem::create_directory(path) && ::chmod(path.c_str(), 0700) == 0;
}

auto prerequisite_name(glove::container::linux_detail::linux_session_prerequisite prerequisite)
    -> std::string_view {
    using glove::container::linux_detail::linux_session_prerequisite;
    switch (prerequisite) {
    case linux_session_prerequisite::available:
        return "available";
    case linux_session_prerequisite::user_namespace_unavailable:
        return "user namespace unavailable";
    case linux_session_prerequisite::cgroup_v2_unavailable:
        return "cgroup v2 unavailable";
    case linux_session_prerequisite::cgroup_controllers_unavailable:
        return "cgroup controllers unavailable";
    case linux_session_prerequisite::cgroup_delegation_unavailable:
        return "cgroup delegation unavailable";
    }
    return "unknown prerequisite state";
}

auto write_owner_file(const std::filesystem::path& path, std::string_view contents) -> bool {
    std::ofstream output{path, std::ios::binary};
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.close();
    return output.good() && ::chmod(path.c_str(), 0600) == 0;
}

auto address_for(const std::filesystem::path& path) -> sockaddr_un {
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto value = path.string();
    std::memcpy(address.sun_path, value.c_str(), value.size() + 1U);
    return address;
}

auto make_listener(const std::filesystem::path& path) -> unique_fd {
    unique_fd listener{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (listener.get() < 0 || path.string().size() >= sizeof(sockaddr_un::sun_path)) {
        return unique_fd{};
    }
    const auto address = address_for(path);
    if (::bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        ::chmod(path.c_str(), 0600) != 0 || ::listen(listener.get(), 8) != 0) {
        return unique_fd{};
    }
    return listener;
}

auto launch_template() -> glove::supervisor::runtime_launch_template {
    return {
        .runtime_discovery = {},
        .executable_path = "/usr/bin/true",
        .executable_search_paths = {},
        .arguments = {},
        .environment = {"PATH=/usr/bin:/bin"},
        .read_only_paths = {},
    };
}

auto validator_for(const std::filesystem::path& source)
    -> glove::supervisor::result<glove::supervisor::session_plan_validator> {
    using namespace glove::supervisor;
    auto paths = path_alias_registry::build({
        path_alias_policy{
            .alias = "workspace",
            .host_path = std::filesystem::canonical(source).string(),
            .target_path = "/workspace",
            .max_ttl_secs = 120,
            .access = {
                path_access_policy{
                    .access = path_access::ephemeral_write,
                    .materialization = path_materialization::copy,
                    .create_policy = path_create_policy::empty_directory,
                    .cleanup_policy = path_cleanup_policy::remove,
                    .max_bytes = 2'097'152,
                },
            },
        },
    });
    if (!paths) {
        return std::unexpected(paths.error());
    }
    const auto digest = runtime_launch_template_digest(launch_template());
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return session_plan_validator::build(
        session_plan_policy{
            .revision = 1,
            .max_plan_ttl_ms = 120'000,
            .runtime_templates =
                {
                    runtime_template_policy{
                        .runtime_template_id = "pi-safe",
                        .runtime_id = "pi",
                        .adapter_command_digest = *digest,
                        .backend = sandbox_backend::linux_production,
                        .allowed_path_aliases = {"workspace"},
                        .allowed_projection_destinations = {},
                        .launch = launch_template(),
                        .adoption = std::nullopt,
                    },
                },
            .library_projection_destinations = {},
            .resource_profiles =
                {
                    resource_limits{
                        .cpu_time_ms = 1'000,
                        .memory_bytes = 67'108'864,
                        .pids = 16,
                        .wall_time_ms = 2'000,
                        .disk_bytes = 2'097'152,
                        .terminal_output_bytes = 1'048'576,
                    },
                },
            .egress_policy_ids = {"no-network"},
            .tool_policy_ids = {"sage-readonly"},
            .secret_handles = {},
            .egress_policies = {},
            .secret_mounts = {},
        },
        std::move(*paths)
    );
}

auto path_grant_for(const std::filesystem::path& source, std::string alias = "service-source")
    -> std::expected<glove::supervisor::resolved_path_grant, std::string> {
    using namespace glove::supervisor;
    auto paths = path_alias_registry::build({
        path_alias_policy{
            .alias = alias,
            .host_path = source.string(),
            .target_path = "/workspace",
            .max_ttl_secs = 120,
            .access = {
                path_access_policy{
                    .access = path_access::read,
                    .materialization = path_materialization::bind,
                    .create_policy = path_create_policy::never,
                    .cleanup_policy = path_cleanup_policy::retain,
                    .max_bytes = 0,
                },
            },
        },
    });
    if (!paths) {
        return std::unexpected(paths.error());
    }
    return paths->resolve({
        .alias = std::move(alias),
        .access = path_access::read,
        .ttl_secs = 60,
        .max_bytes = 0,
    });
}

auto connect_mount(int directory_fd, std::string_view alias) -> int {
    const auto path =
        std::string{"/proc/self/fd/"} + std::to_string(directory_fd) + "/" + std::string{alias};
    if (path.size() >= sizeof(sockaddr_un::sun_path)) {
        return -1;
    }
    const auto address = address_for(path);
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0 ||
        ::connect(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        if (descriptor >= 0) {
            static_cast<void>(::close(descriptor));
        }
        return -1;
    }
    return descriptor;
}

auto descriptor_count() -> std::size_t {
    std::error_code error;
    std::size_t count = 0;
    for ([[maybe_unused]] const auto& entry :
         std::filesystem::directory_iterator{"/proc/self/fd", error}) {
        ++count;
    }
    return error ? 0U : count;
}

[[maybe_unused]] auto directory_entry_count(const std::filesystem::path& path) -> std::size_t {
    std::error_code error;
    std::size_t count = 0;
    for ([[maybe_unused]] const auto& entry : std::filesystem::directory_iterator{path, error}) {
        ++count;
    }
    return error ? std::numeric_limits<std::size_t>::max() : count;
}

auto preparation_inputs(std::uint64_t now_ms) -> glove::control::session_start_inputs {
    const glove::supervisor::resource_limits limits{
        .cpu_time_ms = 10'000,
        .memory_bytes = std::uint64_t{128} * 1024U * 1024U,
        .pids = 16,
        .wall_time_ms = 5'000,
        .disk_bytes = std::uint64_t{16} * 1024U * 1024U,
        .terminal_output_bytes = std::uint64_t{1024} * 1024U,
    };
    return {
        .session =
            {
                .schema_version = 1,
                .session_id = "proxy-preparation",
                .controller_plan_digest = std::string(64U, 'a'),
                .plan_content_digest = std::string(64U, 'b'),
                .state = glove::control::session_state::preparing,
                .policy_revision = 1,
                .expires_at_ms = now_ms + 60'000U,
                .created_at_ms = now_ms - 1U,
            },
        .launch =
            {
                .validation = {.schema_version = 1, .policy_revision = 1},
                .runtime_id = "copilot",
                .runtime_template_id = "copilot-safe",
                .adapter_command_digest = std::string(64U, 'c'),
                .backend = glove::supervisor::sandbox_backend::linux_production,
                .argv = {"/usr/bin/true", "--version"},
                .environment = {"PATH=/usr/bin:/bin", "TERM=xterm-256color"},
                .read_only_paths = {},
                .limits = limits,
                .expires_at_ms = now_ms + 60'000U,
                .requires_direct_write_approval = false,
                .egress_policy_id = "",
                .egress_targets = {},
                .secret_mounts = {},
                .adoption = std::nullopt,
                .refinement = std::nullopt,
            },
        .path_grants = {},
        .library_projections = {},
        .adoption = std::nullopt,
        .authorization_id = "approval-proxy-preparation",
        .authorization_expires_at_ms = now_ms + 30'000U,
    };
}

auto options_for(
    const std::filesystem::path& runtime,
    const std::filesystem::path& endpoint,
    std::shared_ptr<glove::audit::sink> audit,
    std::shared_ptr<const glove::control::guest_channel_adapter_binding> adapter,
    std::uint64_t timeout_ms = 1'000,
    std::uint32_t max_concurrency = 2
) -> glove::control::linux_detail::local_service_proxy_options {
    return {
        .runtime_root = runtime,
        .io_timeout_ms = timeout_ms,
        .max_concurrency = max_concurrency,
        .endpoints =
            {
                glove::control::linux_detail::local_service_endpoint{
                    .alias = "sage-observe",
                    .socket_path = endpoint,
                    .runtime_ids = {"copilot", "pi"},
                },
            },
        .audit = std::move(audit),
        .guest_channel_adapter = std::move(adapter),
    };
}

auto exchange_once(
    int listener, std::string expected_request, std::string response, std::atomic_bool& exact
) -> std::jthread {
    return std::jthread{
        [listener, expected = std::move(expected_request), response = std::move(response), &exact] {
            const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            if (accepted < 0) {
                return;
            }
            auto transport = glove::control::guest_channel_transport::adopt(
                accepted, 16U * 1024U, static_cast<std::uint32_t>(::geteuid())
            );
            if (!transport) {
                return;
            }
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
            auto request = (*transport)->receive_frame(deadline);
            if (!request) {
                return;
            }
            exact = *request == expected;
            static_cast<void>((*transport)->send_frame(response, deadline));
        }
    };
}

// bind_session_mount installs the local-services descriptor with move_mount(2),
// so the proxy mount path must hand out detached open_tree clones. Cloning a
// mount requires mount authority over the current mount namespace; EPERM from
// open_tree(2) positively identifies its absence, and no part of this test can
// exercise the session mount path without it.
auto probe_mount_authority(const std::filesystem::path& probe_directory)
    -> std::expected<bool, std::string> {
    const int directory =
        ::open(probe_directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        return std::unexpected(
            std::string{"open mount authority probe directory: "} + std::strerror(errno)
        );
    }
    const int cloned = static_cast<int>(
        // Linux has no typed libc wrapper for open_tree(2).
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        ::syscall(SYS_open_tree, directory, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)
    );
    const int saved = errno;
    static_cast<void>(::close(directory));
    if (cloned >= 0) {
        static_cast<void>(::close(cloned));
        return true;
    }
    if (saved == EPERM) {
        return false;
    }
    return std::unexpected(std::string{"probe session mount authority: "} + std::strerror(saved));
}

auto run(bool privileged_only) -> int {
    using glove::control::guest_channel_transport;
    using glove::control::linux_detail::local_service_proxy_factory;

    if (privileged_only) {
        const auto prerequisite =
            glove::container::linux_detail::probe_linux_session_prerequisite();
        if (!prerequisite) {
            std::fprintf(
                stderr,
                "Linux capability prerequisite probe failed: %s\n",
                prerequisite.error().c_str()
            );
            return 1;
        }
        if (*prerequisite !=
            glove::container::linux_detail::linux_session_prerequisite::available) {
            const auto reason = prerequisite_name(*prerequisite);
            std::fprintf(
                stderr,
                "SKIP concrete Linux capability sealing: %.*s\n",
                static_cast<int>(reason.size()),
                reason.data()
            );
            return 77;
        }
    }

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto mount_probe_directory = temporary.root() / "mount-authority-probe";
    REQUIRE(make_owner_directory(mount_probe_directory));
    const auto mount_authority = probe_mount_authority(mount_probe_directory);
    REQUIRE(mount_authority.has_value());
    if (!*mount_authority) {
        std::fprintf(stderr, "SKIP session mount authority (open_tree/move_mount) unavailable\n");
        return 77;
    }
    const auto source = temporary.root() / "source";
    const auto runtime = temporary.root() / "runtime";
    const auto upstream = temporary.root() / "upstream";
    REQUIRE(make_owner_directory(source));
    REQUIRE(make_owner_directory(runtime));
    REQUIRE(make_owner_directory(upstream));
    const auto endpoint = upstream / "sage.sock";
    auto listener = make_listener(endpoint);
    REQUIRE(listener.get() >= 0);

    auto validator = validator_for(source);
    REQUIRE(validator.has_value());
    auto shared_validator =
        std::make_shared<const glove::supervisor::session_plan_validator>(std::move(*validator));

    // Regression (Workflow #218 Ghost E2E): bind_session_mount installs the
    // local-services descriptor with move_mount(2), which only accepts a
    // detached mount. The descriptor produced by mount() must therefore be an
    // open_tree clone of the proxy session directory, not a plain directory
    // descriptor; a plain descriptor fails there with EINVAL. Uses a dedicated
    // runtime root so the assertion is independent of the shared-runtime
    // scenarios below. Requires mount authority, guaranteed by the gate above.
    {
        const auto provenance_runtime = temporary.root() / "provenance-runtime";
        REQUIRE(make_owner_directory(provenance_runtime));
        auto provenance_registry_result = glove::control::session_registry::open_or_create(
            temporary.root() / "provenance-sessions.journal", shared_validator
        );
        REQUIRE(provenance_registry_result.has_value());
        auto provenance_registry = std::shared_ptr<glove::control::session_registry>{
            std::move(*provenance_registry_result)
        };
        auto provenance_factory = local_service_proxy_factory::create(
            options_for(provenance_runtime, endpoint, glove::audit::make_memory_sink(), {}),
            provenance_registry
        );
        REQUIRE(provenance_factory.has_value());
        auto provenance_session =
            (*provenance_factory)->prepare_session("mount-detached-provenance", "pi");
        REQUIRE(provenance_session.has_value());
        auto provenance_mount = (*provenance_session)->mount();
        REQUIRE(provenance_mount.has_value());
        unique_fd provenance_descriptor{provenance_mount->descriptor_fd};
        provenance_mount->descriptor_fd = -1;
        REQUIRE(provenance_descriptor.get() >= 0);
        const auto attach_target = temporary.root() / "mount-provenance-attach";
        REQUIRE(make_owner_directory(attach_target));
        const int attached = static_cast<int>(
            // Linux has no typed libc wrapper for move_mount(2).
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg,hicpp-vararg)
            ::syscall(
                SYS_move_mount,
                provenance_descriptor.get(),
                "",
                AT_FDCWD,
                attach_target.c_str(),
                MOVE_MOUNT_F_EMPTY_PATH
            )
        );
        if (attached != 0) {
            std::fprintf(
                stderr,
                "local-services mount descriptor is not a detached mount: %s\n",
                std::strerror(errno)
            );
            return 1;
        }
        REQUIRE(::syscall(SYS_umount2, attach_target.c_str(), MNT_DETACH) == 0);
        REQUIRE(::rmdir(attach_target.c_str()) == 0);
    }

    auto adapter = glove::adapters::sage::resolve_guest_channel_adapter(
        "sage-observation", "sage.glove-observation.v1"
    );
    REQUIRE(adapter.has_value());
    const auto catalog = (*adapter)->channels;
    auto registry = glove::control::session_registry::open_or_create(
        temporary.root() / "sessions.journal",
        shared_validator,
        {},
        glove::control::default_session_registry_bytes,
        catalog
    );
    REQUIRE(registry.has_value());
    auto shared_registry = std::shared_ptr<glove::control::session_registry>{std::move(*registry)};
    // Regression (Workflow #218 Ghost E2E): every prepare_session mkdirat(2)s
    // a svc-* staging directory under the runtime root, and on ext4/tmpfs/APFS
    // a directory's st_nlink is 2 plus its subdirectory count. The operational
    // identity must therefore not pin the runtime root's link count: two
    // factories sharing one runtime root - and one factory preparing
    // consecutive sessions - must both stay operational across a
    // prepare_session. On the pre-fix baseline the first prepare_session of a
    // second factory sharing the root failed here as false "identity drift"
    // (nlink 2 -> 3; Ghost LastTest.log line 666). Permission drift on the
    // root must still fail closed, and endpoint sockets keep their exact
    // dev/ino/uid/mode/nlink recheck (unchanged endpoint_current). Both
    // factories use the shared registry and the same adapter binding, the
    // only supported sharing shape.
    {
        const auto shared_runtime_root = temporary.root() / "shared-runtime-root";
        REQUIRE(make_owner_directory(shared_runtime_root));
        auto first_factory = local_service_proxy_factory::create(
            options_for(shared_runtime_root, endpoint, glove::audit::make_memory_sink(), *adapter),
            shared_registry
        );
        REQUIRE(first_factory.has_value());
        REQUIRE((*first_factory)->operational());
        auto first_session = (*first_factory)->prepare_session("shared-root-a", "pi");
        REQUIRE(first_session.has_value());
        REQUIRE((*first_factory)->operational());
        auto second_factory = local_service_proxy_factory::create(
            options_for(shared_runtime_root, endpoint, glove::audit::make_memory_sink(), *adapter),
            shared_registry
        );
        REQUIRE(second_factory.has_value());
        REQUIRE((*second_factory)->operational());
        auto second_session = (*second_factory)->prepare_session("shared-root-b", "pi");
        REQUIRE(second_session.has_value());
        REQUIRE((*second_factory)->operational());
        REQUIRE((*first_factory)->operational());
        REQUIRE(::chmod(shared_runtime_root.c_str(), 0755) == 0);
        REQUIRE(!(*first_factory)->operational());
        REQUIRE(!(*second_factory)->operational());
        REQUIRE(::chmod(shared_runtime_root.c_str(), 0700) == 0);
        REQUIRE((*first_factory)->operational());
        REQUIRE((*second_factory)->operational());
    }

    auto audit = glove::audit::make_memory_sink();
    auto factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, audit, *adapter), shared_registry
    );
    REQUIRE(factory.has_value());
    REQUIRE((*factory)->operational());
    REQUIRE(::chmod(runtime.c_str(), 0755) == 0);
    REQUIRE(!(*factory)->operational());
    REQUIRE(::chmod(runtime.c_str(), 0700) == 0);
    REQUIRE((*factory)->operational());
    REQUIRE((*factory)->manages_runtime("pi"));
    REQUIRE(!(*factory)->manages_runtime("codex"));

    auto direct_parent_grant = path_grant_for(upstream, "direct-parent");
    REQUIRE(direct_parent_grant.has_value());
    auto direct_parent_result = (*factory)->validate_path_grants(
        std::span<const glove::supervisor::resolved_path_grant>{&*direct_parent_grant, 1U}
    );
    REQUIRE(!direct_parent_result.has_value());
    REQUIRE(direct_parent_result.error().find(upstream.string()) == std::string::npos);

    auto grandparent_grant = path_grant_for(temporary.root(), "grandparent");
    REQUIRE(grandparent_grant.has_value());
    REQUIRE(
        !(*factory)
             ->validate_path_grants(
                 std::span<const glove::supervisor::resolved_path_grant>{&*grandparent_grant, 1U}
             )
             .has_value()
    );

    auto unrelated_grant = path_grant_for(source, "unrelated");
    REQUIRE(unrelated_grant.has_value());
    REQUIRE((*factory)
                ->validate_path_grants(
                    std::span<const glove::supervisor::resolved_path_grant>{&*unrelated_grant, 1U}
                )
                .has_value());
    REQUIRE(!path_grant_for(endpoint, "exact-socket").has_value());

    const auto real_endpoint_root = temporary.root() / "real-endpoint-root";
    const auto real_endpoint_parent = real_endpoint_root / "child";
    REQUIRE(make_owner_directory(real_endpoint_root));
    REQUIRE(make_owner_directory(real_endpoint_parent));
    const auto aliased_endpoint = real_endpoint_parent / "aliased.sock";
    auto aliased_listener = make_listener(aliased_endpoint);
    REQUIRE(aliased_listener.get() >= 0);
    const auto endpoint_root_alias = temporary.root() / "endpoint-root-alias";
    REQUIRE(::symlink(real_endpoint_root.c_str(), endpoint_root_alias.c_str()) == 0);
    auto alias_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint_root_alias / "child/aliased.sock", audit, *adapter),
        shared_registry
    );
    REQUIRE(alias_factory.has_value());
    auto aliased_parent_grant = path_grant_for(real_endpoint_parent, "aliased-parent");
    REQUIRE(aliased_parent_grant.has_value());
    REQUIRE(
        !(*alias_factory)
             ->validate_path_grants(
                 std::span<const glove::supervisor::resolved_path_grant>{&*aliased_parent_grant, 1U}
             )
             .has_value()
    );

    auto equivalent_adapter = glove::adapters::sage::resolve_guest_channel_adapter(
        "sage-observation", "sage.glove-observation.v1"
    );
    REQUIRE(equivalent_adapter.has_value());
    REQUIRE(!local_service_proxy_factory::create(
                 options_for(runtime, endpoint, audit, *equivalent_adapter), shared_registry
    )
                 .has_value());

    auto mismatched_adapter = std::make_shared<const glove::control::guest_channel_adapter_binding>(
        glove::control::guest_channel_adapter_binding{
            .adapter_id = "sage-observation",
            .channel_schema_id = "sage.unregistered.v1",
            .runtime_ids = {"pi"},
            .channels = catalog,
        }
    );
    REQUIRE(!local_service_proxy_factory::create(
                 options_for(runtime, endpoint, audit, std::move(mismatched_adapter)),
                 shared_registry
    )
                 .has_value());

    auto generic_registry_result = glove::control::session_registry::open_or_create(
        temporary.root() / "generic-sessions.journal", shared_validator
    );
    REQUIRE(generic_registry_result.has_value());
    auto generic_registry =
        std::shared_ptr<glove::control::session_registry>{std::move(*generic_registry_result)};
    auto generic_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, audit, {}), generic_registry
    );
    REQUIRE(generic_factory.has_value());
    REQUIRE((*generic_factory)->operational());
    auto generic_session = (*generic_factory)->prepare_session("generic-session", "pi");
    REQUIRE(generic_session.has_value());
    auto generic_mount = (*generic_session)->mount();
    REQUIRE(generic_mount.has_value());
    REQUIRE(::close(generic_mount->descriptor_fd) == 0);
    generic_mount->descriptor_fd = -1;

    auto session = (*factory)->prepare_session("session-1", "pi");
    REQUIRE(session.has_value());
    REQUIRE(!(*factory)->prepare_session("session-2", "codex").has_value());
    auto mount = (*session)->mount();
    REQUIRE(mount.has_value());
    REQUIRE(mount->alias == "local-services");
    REQUIRE(mount->target_path == "/run/glove-services/local");
    REQUIRE(mount->directory && !mount->writable);
    REQUIRE(mount->service_proxy_manifest_digest.has_value());
    REQUIRE((::fcntl(mount->descriptor_fd, F_GETFD) & FD_CLOEXEC) != 0);
    unique_fd mount_fd{mount->descriptor_fd};
    mount->descriptor_fd = -1;

    const std::string request{"opaque\0request", 14U};
    const std::string response{"opaque\0response", 15U};
    std::atomic_bool exact{false};
    auto upstream_exchange = exchange_once(listener.get(), request, response, exact);
    auto client = guest_channel_transport::adopt(
        connect_mount(mount_fd.get(), "sage-observe"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(client.has_value());
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
    REQUIRE((*client)->send_frame(request, deadline).has_value());
    auto received = (*client)->receive_frame(deadline);
    REQUIRE(received.has_value());
    REQUIRE(*received == response);
    upstream_exchange.join();
    REQUIRE(exact.load());
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    auto events = audit->take();
    REQUIRE(events.size() == 2U);
    REQUIRE(events.front().what == glove::audit::action::local_service);
    REQUIRE(events.front().tool_name == "session-1:sage-observe");
    REQUIRE(events.front().arguments_json.empty());
    REQUIRE(events.front().status == glove::mcp::tool_call_status::transport_error);
    REQUIRE(events.front().error_message == "delivery_pending");
    REQUIRE(events.back().status == glove::mcp::tool_call_status::ok);
    REQUIRE(events.back().error_message == "delivered");

    std::jthread disconnect_upstream{[listener = listener.get()] {
        const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        auto transport = guest_channel_transport::adopt(
            accepted, 16U * 1024U, static_cast<std::uint32_t>(::geteuid())
        );
        if (!transport) {
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
        auto request = (*transport)->receive_frame(deadline);
        if (!request) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        static_cast<void>((*transport)->send_frame("disconnect-response", deadline));
    }};
    auto disconnect_client = guest_channel_transport::adopt(
        connect_mount(mount_fd.get(), "sage-observe"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(disconnect_client.has_value());
    const auto disconnect_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE((*disconnect_client)->send_frame("disconnect", disconnect_deadline).has_value());
    disconnect_client->reset();
    disconnect_upstream.join();
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
    auto disconnect_events = audit->take();
    REQUIRE(disconnect_events.size() == 2U);
    REQUIRE(disconnect_events.front().error_message == "delivery_pending");
    REQUIRE(disconnect_events.back().error_message == "delivery_failed");
    REQUIRE(std::ranges::none_of(disconnect_events, [](const auto& event) {
        return event.status == glove::mcp::tool_call_status::ok;
    }));

    auto terminal_failure_audit = std::make_shared<fail_terminal_sink>();
    auto terminal_failure_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, terminal_failure_audit, *adapter), shared_registry
    );
    REQUIRE(terminal_failure_factory.has_value());
    auto terminal_failure_session =
        (*terminal_failure_factory)->prepare_session("terminal-audit-failure", "pi");
    REQUIRE(terminal_failure_session.has_value());
    auto terminal_failure_mount = (*terminal_failure_session)->mount();
    REQUIRE(terminal_failure_mount.has_value());
    unique_fd terminal_failure_mount_fd{terminal_failure_mount->descriptor_fd};
    terminal_failure_mount->descriptor_fd = -1;
    std::atomic_bool terminal_failure_exact{false};
    auto terminal_failure_upstream = exchange_once(
        listener.get(), "terminal-failure", "terminal-response", terminal_failure_exact
    );
    auto terminal_failure_client = guest_channel_transport::adopt(
        connect_mount(terminal_failure_mount_fd.get(), "sage-observe"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(terminal_failure_client.has_value());
    const auto terminal_failure_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE((*terminal_failure_client)
                ->send_frame("terminal-failure", terminal_failure_deadline)
                .has_value());
    auto terminal_response = (*terminal_failure_client)->receive_frame(terminal_failure_deadline);
    REQUIRE(terminal_response.has_value());
    REQUIRE(*terminal_response == "terminal-response");
    terminal_failure_upstream.join();
    auto terminal_failure_events = terminal_failure_audit->take();
    REQUIRE(terminal_failure_events.size() == 1U);
    REQUIRE(terminal_failure_events.front().error_message == "delivery_pending");
    REQUIRE(
        terminal_failure_events.front().status == glove::mcp::tool_call_status::transport_error
    );

    auto timeout_audit = glove::audit::make_memory_sink();
    auto timeout_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, timeout_audit, *adapter, 100, 1), shared_registry
    );
    REQUIRE(timeout_factory.has_value());
    auto timeout_session = (*timeout_factory)->prepare_session("timeout", "pi");
    REQUIRE(timeout_session.has_value());
    auto timeout_identity_mount = (*timeout_session)->mount();
    REQUIRE(timeout_identity_mount.has_value());
    REQUIRE(
        timeout_identity_mount->service_proxy_manifest_digest !=
        mount->service_proxy_manifest_digest
    );
    REQUIRE(::close(timeout_identity_mount->descriptor_fd) == 0);
    timeout_identity_mount->descriptor_fd = -1;
    auto timeout_mount = (*timeout_session)->mount();
    REQUIRE(timeout_mount.has_value());
    unique_fd timeout_mount_fd{timeout_mount->descriptor_fd};
    timeout_mount->descriptor_fd = -1;
    std::jthread slow_upstream{[listener = listener.get()] {
        const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        auto transport = guest_channel_transport::adopt(
            accepted, 16U * 1024U, static_cast<std::uint32_t>(::geteuid())
        );
        if (!transport) {
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
        if ((*transport)->receive_frame(deadline)) {
            std::this_thread::sleep_for(std::chrono::milliseconds{250});
        }
    }};
    auto timeout_client = guest_channel_transport::adopt(
        connect_mount(timeout_mount_fd.get(), "sage-observe"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(timeout_client.has_value());
    const auto timeout_started = std::chrono::steady_clock::now();
    const auto timeout_deadline = timeout_started + std::chrono::seconds{1};
    REQUIRE((*timeout_client)->send_frame("trickle-safe", timeout_deadline).has_value());
    REQUIRE(!(*timeout_client)->receive_frame(timeout_deadline).has_value());
    REQUIRE(std::chrono::steady_clock::now() - timeout_started < std::chrono::milliseconds{500});
    slow_upstream.join();
    auto timeout_events = timeout_audit->take();
    REQUIRE(timeout_events.size() <= 1U);
    REQUIRE(std::ranges::none_of(timeout_events, [](const auto& event) {
        return event.status == glove::mcp::tool_call_status::ok;
    }));
    if (!timeout_events.empty()) {
        REQUIRE(timeout_events.front().arguments_json.empty());
        REQUIRE(timeout_events.front().error_message == "delivery_failed");
    }

    auto slow_audit = std::make_shared<delayed_sink>(std::chrono::milliseconds{150});
    auto slow_audit_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, slow_audit, *adapter, 100, 1), shared_registry
    );
    REQUIRE(slow_audit_factory.has_value());
    auto slow_audit_session = (*slow_audit_factory)->prepare_session("audit-deadline", "pi");
    REQUIRE(slow_audit_session.has_value());
    auto slow_audit_mount = (*slow_audit_session)->mount();
    REQUIRE(slow_audit_mount.has_value());
    unique_fd slow_audit_mount_fd{slow_audit_mount->descriptor_fd};
    slow_audit_mount->descriptor_fd = -1;
    std::atomic_bool slow_audit_exact{false};
    auto slow_audit_upstream =
        exchange_once(listener.get(), "audit-deadline", "late-response", slow_audit_exact);
    auto slow_audit_client = guest_channel_transport::adopt(
        connect_mount(slow_audit_mount_fd.get(), "sage-observe"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(slow_audit_client.has_value());
    const auto slow_audit_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE((*slow_audit_client)->send_frame("audit-deadline", slow_audit_deadline).has_value());
    REQUIRE(!(*slow_audit_client)->receive_frame(slow_audit_deadline).has_value());
    slow_audit_upstream.join();
    auto slow_audit_events = slow_audit->take();
    REQUIRE(slow_audit_events.size() == 1U);
    REQUIRE(slow_audit_events.front().error_message == "delivery_pending");
    REQUIRE(slow_audit_events.front().status == glove::mcp::tool_call_status::transport_error);

    auto bounded_audit = glove::audit::make_memory_sink();
    auto bounded_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, bounded_audit, *adapter, 1'000, 1), shared_registry
    );
    REQUIRE(bounded_factory.has_value());
    auto bounded_session = (*bounded_factory)->prepare_session("bounded", "pi");
    REQUIRE(bounded_session.has_value());
    auto bounded_mount = (*bounded_session)->mount();
    REQUIRE(bounded_mount.has_value());
    unique_fd bounded_mount_fd{bounded_mount->descriptor_fd};
    bounded_mount->descriptor_fd = -1;
    std::atomic_int active{0};
    std::atomic_int maximum{0};
    std::jthread bounded_upstream{[listener = listener.get(), &active, &maximum] {
        std::vector<std::thread> handlers;
        for (int request_index = 0; request_index < 2; ++request_index) {
            const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            if (accepted < 0) {
                return;
            }
            handlers.emplace_back([accepted, &active, &maximum] {
                auto transport = guest_channel_transport::adopt(
                    accepted, 16U * 1024U, static_cast<std::uint32_t>(::geteuid())
                );
                if (!transport) {
                    return;
                }
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
                auto request = (*transport)->receive_frame(deadline);
                if (!request) {
                    return;
                }
                const int current = active.fetch_add(1) + 1;
                maximum.store(std::max(maximum.load(), current));
                std::this_thread::sleep_for(std::chrono::milliseconds{100});
                active.fetch_sub(1);
                static_cast<void>((*transport)->send_frame(*request, deadline));
            });
        }
        for (auto& handler : handlers) {
            handler.join();
        }
    }};
    std::atomic_int bounded_successes{0};
    auto bounded_client = [&](std::string payload) {
        auto transport = guest_channel_transport::adopt(
            connect_mount(bounded_mount_fd.get(), "sage-observe"),
            16U * 1024U,
            static_cast<std::uint32_t>(::geteuid())
        );
        if (!transport) {
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        if ((*transport)->send_frame(payload, deadline)) {
            auto response = (*transport)->receive_frame(deadline);
            if (response && *response == payload) {
                bounded_successes.fetch_add(1);
            }
        }
    };
    std::jthread first_bounded{bounded_client, "one"};
    std::jthread second_bounded{bounded_client, "two"};
    first_bounded.join();
    second_bounded.join();
    bounded_upstream.join();
    REQUIRE(bounded_successes.load() == 2);
    REQUIRE(maximum.load() == 1);

    const auto later_endpoint = upstream / "later.sock";
    auto later_listener = make_listener(later_endpoint);
    REQUIRE(later_listener.get() >= 0);

    auto non_pi_options = options_for(runtime, endpoint, audit, *adapter, 1'000, 1);
    non_pi_options.endpoints = {
        {
            .alias = "codex-only",
            .socket_path = endpoint,
            .runtime_ids = {"codex"},
        },
        {
            .alias = "opencode-only",
            .socket_path = later_endpoint,
            .runtime_ids = {"opencode"},
        },
    };
    auto non_pi_factory =
        local_service_proxy_factory::create(std::move(non_pi_options), shared_registry);
    REQUIRE(non_pi_factory.has_value());
    REQUIRE((*non_pi_factory)->prepare_session("codex-session", "codex").has_value());
    REQUIRE((*non_pi_factory)->prepare_session("opencode-session", "opencode").has_value());

    auto fair_options = options_for(runtime, endpoint, audit, *adapter, 2'000, 1);
    fair_options.endpoints = {
        {
            .alias = "a-hot",
            .socket_path = endpoint,
            .runtime_ids = {"pi"},
        },
        {
            .alias = "z-later",
            .socket_path = later_endpoint,
            .runtime_ids = {"pi"},
        },
    };
    auto fair_factory =
        local_service_proxy_factory::create(std::move(fair_options), shared_registry);
    REQUIRE(fair_factory.has_value());
    auto fair_session = (*fair_factory)->prepare_session("fair", "pi");
    REQUIRE(fair_session.has_value());
    auto fair_mount = (*fair_session)->mount();
    REQUIRE(fair_mount.has_value());
    unique_fd fair_mount_fd{fair_mount->descriptor_fd};
    fair_mount->descriptor_fd = -1;
    std::jthread hot_upstream{[listener = listener.get()] {
        for (int index = 0; index < 4; ++index) {
            const int accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            auto transport = guest_channel_transport::adopt(
                accepted, 16U * 1024U, static_cast<std::uint32_t>(::geteuid())
            );
            if (!transport) {
                return;
            }
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
            auto request = (*transport)->receive_frame(deadline);
            if (!request) {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{75});
            static_cast<void>((*transport)->send_frame(*request, deadline));
        }
    }};
    std::atomic_bool later_exact{false};
    auto later_upstream =
        exchange_once(later_listener.get(), "later-request", "later-response", later_exact);
    std::vector<std::unique_ptr<guest_channel_transport>> hot_clients;
    hot_clients.reserve(4U);
    for (int index = 0; index < 4; ++index) {
        auto hot_client = guest_channel_transport::adopt(
            connect_mount(fair_mount_fd.get(), "a-hot"),
            16U * 1024U,
            static_cast<std::uint32_t>(::geteuid())
        );
        REQUIRE(hot_client.has_value());
        const auto client_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        REQUIRE(
            (*hot_client)->send_frame("hot-" + std::to_string(index), client_deadline).has_value()
        );
        hot_clients.push_back(std::move(*hot_client));
    }
    auto later_client = guest_channel_transport::adopt(
        connect_mount(fair_mount_fd.get(), "z-later"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(later_client.has_value());
    const auto later_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{250};
    REQUIRE((*later_client)->send_frame("later-request", later_deadline).has_value());
    auto later_response = (*later_client)->receive_frame(later_deadline);
    REQUIRE(later_response.has_value());
    REQUIRE(*later_response == "later-response");
    later_upstream.join();
    REQUIRE(later_exact.load());
    for (auto& hot_client : hot_clients) {
        const auto hot_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        REQUIRE(hot_client->receive_frame(hot_deadline).has_value());
    }
    hot_upstream.join();

    if (privileged_only) {
        const auto materializations = temporary.root() / "materializations";
        REQUIRE(make_owner_directory(materializations));
        auto preparer_result = glove::control::linux_detail::linux_session_preparer::create(
            materializations.string(), audit, *factory
        );
        if (!preparer_result) {
            std::fprintf(
                stderr,
                "Linux capability setup failed: %s\n",
                preparer_result.error().c_str()
            );
            return 1;
        }
        auto preparer = std::make_shared<glove::control::linux_detail::linux_session_preparer>(
            std::move(*preparer_result)
        );
        const auto now_ms =
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::system_clock::now().time_since_epoch()
            )
                                           .count());
        {
            auto pi_only_options = options_for(runtime, endpoint, audit, *adapter);
            pi_only_options.endpoints.front().runtime_ids = {"pi"};
            auto pi_only_factory =
                local_service_proxy_factory::create(std::move(pi_only_options), shared_registry);
            REQUIRE(pi_only_factory.has_value());
            auto pi_only_preparer = glove::control::linux_detail::linux_session_preparer::create(
                materializations.string(), audit, *pi_only_factory
            );
            REQUIRE(pi_only_preparer.has_value());
            auto denied_grant = path_grant_for(upstream, "non-allowlisted-runtime-parent");
            REQUIRE(denied_grant.has_value());
            auto denied_inputs = preparation_inputs(now_ms);
            denied_inputs.session.session_id = "proxy-path-non-allowlisted-runtime";
            denied_inputs.authorization_id = "approval-proxy-path-non-allowlisted-runtime";
            denied_inputs.path_grants.push_back(std::move(*denied_grant));
            REQUIRE(!pi_only_preparer->prepare(std::move(denied_inputs), now_ms).has_value());
            REQUIRE(std::filesystem::is_empty(materializations));

            auto blocked_inputs = preparation_inputs(now_ms);
            blocked_inputs.session.session_id = "proxy-path-conflict";
            blocked_inputs.authorization_id = "approval-proxy-path-conflict";
            blocked_inputs.path_grants.push_back(std::move(*direct_parent_grant));
            auto blocked = preparer->prepare(std::move(blocked_inputs), now_ms);
            REQUIRE(!blocked.has_value());
            REQUIRE(blocked.error().find(upstream.string()) == std::string::npos);
            REQUIRE(std::filesystem::is_empty(materializations));

            auto prepared = preparer->prepare(preparation_inputs(now_ms), now_ms);
            REQUIRE(prepared.has_value());
            REQUIRE(prepared->local_service_proxy != nullptr);
            REQUIRE(
                std::ranges::find(
                    prepared->profile.environment,
                    "GLOVE_LOCAL_SERVICE_DIR=/run/glove-services/local"
                ) != prepared->profile.environment.end()
            );
            const auto mounts = prepared->lifecycle->mounts();
            const auto service_mount = std::ranges::find(
                mounts,
                std::string{"/run/glove-services/local"},
                &glove::supervisor::linux_detail::session_mount::target_path
            );
            REQUIRE(service_mount != mounts.end());
            REQUIRE(service_mount->alias == "local-services");
            REQUIRE(service_mount->directory && !service_mount->writable);
            REQUIRE(
                service_mount->service_proxy_manifest_digest ==
                prepared->binding.service_proxy_manifest_digest
            );
        }
#if !GLOVE_LOCAL_PROXY_TSAN
        unique_fd reused_install_descriptor;
        {
            auto plain_preparer_result =
                glove::control::linux_detail::linux_session_preparer::create(
                    materializations.string(), audit
                );
            REQUIRE(plain_preparer_result.has_value());
            auto plain_prepared =
                plain_preparer_result->prepare(preparation_inputs(now_ms + 1U), now_ms + 1U);
            REQUIRE(plain_prepared.has_value());
            auto install_session = (*factory)->prepare_session("install-allocation-fault", "pi");
            REQUIRE(install_session.has_value());
            auto install_mount = (*install_session)->mount();
            REQUIRE(install_mount.has_value());
            const int transferred_descriptor = install_mount->descriptor_fd;
            const auto before_install = descriptor_count() - 1U;
            allocation_fault::remaining.store(0);
            auto installed =
                plain_prepared->lifecycle->install_service_mount(std::move(*install_mount));
            allocation_fault::remaining.store(-1);
            REQUIRE(!installed.has_value());
            REQUIRE(::fcntl(transferred_descriptor, F_GETFD) == -1);
            REQUIRE(errno == EBADF);
            const auto after_install = descriptor_count();
            if (after_install != before_install) {
                std::fprintf(
                    stderr,
                    "install allocation descriptor drift: before=%zu after=%zu\n",
                    before_install,
                    after_install
                );
            }
            REQUIRE(after_install == before_install);
            reused_install_descriptor = unique_fd{::open("/dev/null", O_RDONLY | O_CLOEXEC)};
            REQUIRE(reused_install_descriptor.get() == transferred_descriptor);
        }
        REQUIRE(::fcntl(reused_install_descriptor.get(), F_GETFD) >= 0);
#endif

        auto runtime_result = glove::control::linux_detail::linux_session_runtime::create(
            shared_registry, preparer, {}
        );
        REQUIRE(runtime_result.has_value());
        auto concrete_runtime =
            std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
                std::move(*runtime_result)
        };
        REQUIRE(::chmod(endpoint.c_str(), 0660) == 0);
        auto stale_endpoint_capability = (*factory)->try_seal(concrete_runtime);
        REQUIRE(!stale_endpoint_capability.has_value());
        REQUIRE(::chmod(endpoint.c_str(), 0600) == 0);
        REQUIRE(::chmod(runtime.c_str(), 0755) == 0);
        auto stale_root_capability = (*factory)->try_seal(concrete_runtime);
        REQUIRE(!stale_root_capability.has_value());
        REQUIRE(::chmod(runtime.c_str(), 0700) == 0);

        auto sealed_result = (*factory)->try_seal(concrete_runtime);
        REQUIRE(sealed_result.has_value());
        REQUIRE(sealed_result->has_value());
        auto sealed = std::move(**sealed_result);
        REQUIRE(sealed->operational_for(concrete_runtime.get(), shared_registry.get()));
#if !GLOVE_LOCAL_PROXY_TSAN
        allocation_fault::remaining.store(0);
        auto failed_capability = (*factory)->try_seal(concrete_runtime);
        allocation_fault::remaining.store(-1);
        REQUIRE(!failed_capability.has_value());
#endif

        auto lifetime_registry_result = glove::control::session_registry::open_or_create(
            temporary.root() / "lifetime-sessions.journal",
            shared_validator,
            {},
            glove::control::default_session_registry_bytes,
            catalog
        );
        REQUIRE(lifetime_registry_result.has_value());
        auto lifetime_registry =
            std::shared_ptr<glove::control::session_registry>{std::move(*lifetime_registry_result)};
        auto registry_mismatch_runtime_result =
            glove::control::linux_detail::linux_session_runtime::create(
                lifetime_registry, preparer, {}
            );
        REQUIRE(registry_mismatch_runtime_result.has_value());
        auto registry_mismatch_runtime =
            std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
                std::move(*registry_mismatch_runtime_result)
        };
        auto registry_mismatch_capability =
            (*factory)->try_seal(std::move(registry_mismatch_runtime));
        REQUIRE(!registry_mismatch_capability.has_value());

        auto lifetime_factory_result = local_service_proxy_factory::create(
            options_for(runtime, endpoint, audit, *adapter), lifetime_registry
        );
        REQUIRE(lifetime_factory_result.has_value());
        auto lifetime_factory = std::move(*lifetime_factory_result);
        auto lifetime_preparer_result =
            glove::control::linux_detail::linux_session_preparer::create(
                materializations.string(), audit, lifetime_factory
            );
        REQUIRE(lifetime_preparer_result.has_value());
        auto lifetime_preparer =
            std::make_shared<glove::control::linux_detail::linux_session_preparer>(
                std::move(*lifetime_preparer_result)
            );
        auto lifetime_runtime_result = glove::control::linux_detail::linux_session_runtime::create(
            lifetime_registry, lifetime_preparer, {}
        );
        REQUIRE(lifetime_runtime_result.has_value());
        auto lifetime_runtime =
            std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
                std::move(*lifetime_runtime_result)
        };
        auto lifetime_capability_result = lifetime_factory->try_seal(lifetime_runtime);
        REQUIRE(lifetime_capability_result.has_value());
        REQUIRE(lifetime_capability_result->has_value());
        auto lifetime_capability = std::move(**lifetime_capability_result);
        const auto* lifetime_runtime_identity = lifetime_runtime.get();
        const auto* lifetime_registry_identity = lifetime_registry.get();
        std::weak_ptr<glove::control::session_registry> weak_lifetime_registry = lifetime_registry;
        std::weak_ptr<glove::control::linux_detail::linux_session_preparer> weak_lifetime_preparer =
            lifetime_preparer;
        std::weak_ptr<local_service_proxy_factory> weak_lifetime_factory = lifetime_factory;
        std::weak_ptr<glove::control::linux_detail::linux_session_runtime> weak_lifetime_runtime =
            lifetime_runtime;
        lifetime_runtime.reset();
        lifetime_preparer.reset();
        lifetime_factory.reset();
        lifetime_registry.reset();
        REQUIRE(lifetime_capability->operational_for(
            lifetime_runtime_identity, lifetime_registry_identity
        ));
        auto lifetime_sessions = lifetime_runtime_identity->list();
        REQUIRE(lifetime_sessions.has_value());
        REQUIRE(lifetime_sessions->empty());
        REQUIRE(!weak_lifetime_runtime.expired());
        REQUIRE(!weak_lifetime_preparer.expired());
        REQUIRE(!weak_lifetime_factory.expired());
        REQUIRE(!weak_lifetime_registry.expired());
        lifetime_capability.reset();
        REQUIRE(weak_lifetime_runtime.expired());
        REQUIRE(weak_lifetime_preparer.expired());
        REQUIRE(weak_lifetime_factory.expired());
        REQUIRE(weak_lifetime_registry.expired());

        auto generic_options = options_for(runtime, endpoint, audit, {}, 1'000, 1);
        auto generic_pi_factory =
            local_service_proxy_factory::create(std::move(generic_options), shared_registry);
        REQUIRE(generic_pi_factory.has_value());
        auto generic_preparer_result = glove::control::linux_detail::linux_session_preparer::create(
            materializations.string(), audit, *generic_pi_factory
        );
        REQUIRE(generic_preparer_result.has_value());
        auto generic_preparer =
            std::make_shared<glove::control::linux_detail::linux_session_preparer>(
                std::move(*generic_preparer_result)
            );
        auto generic_runtime = glove::control::linux_detail::linux_session_runtime::create(
            shared_registry, generic_preparer, {}
        );
        REQUIRE(generic_runtime.has_value());
        auto generic_runtime_shared =
            std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
                std::move(*generic_runtime)
        };
        auto generic_capability = (*generic_pi_factory)->try_seal(generic_runtime_shared);
        REQUIRE(generic_capability.has_value());
        REQUIRE(!generic_capability->has_value());

        auto non_pi_preparer_result = glove::control::linux_detail::linux_session_preparer::create(
            materializations.string(), audit, *non_pi_factory
        );
        REQUIRE(non_pi_preparer_result.has_value());
        auto non_pi_preparer =
            std::make_shared<glove::control::linux_detail::linux_session_preparer>(
                std::move(*non_pi_preparer_result)
            );
        auto non_pi_runtime = glove::control::linux_detail::linux_session_runtime::create(
            shared_registry, non_pi_preparer, {}
        );
        REQUIRE(non_pi_runtime.has_value());
        auto non_pi_runtime_shared =
            std::shared_ptr<glove::control::linux_detail::linux_session_runtime>{
                std::move(*non_pi_runtime)
        };
        REQUIRE((*non_pi_factory)->manages_runtime("codex"));
        REQUIRE((*non_pi_factory)->manages_runtime("opencode"));
        auto non_pi_capability = (*non_pi_factory)->try_seal(non_pi_runtime_shared);
        REQUIRE(non_pi_capability.has_value());
        REQUIRE(!non_pi_capability->has_value());

        auto mismatched_factory = local_service_proxy_factory::create(
            options_for(runtime, endpoint, audit, *adapter), shared_registry
        );
        REQUIRE(mismatched_factory.has_value());
        auto mismatched_capability = (*mismatched_factory)->try_seal(concrete_runtime);
        REQUIRE(!mismatched_capability.has_value());

        constexpr std::string_view bootstrap_secret =
            "1111111111111111111111111111111111111111111111111111111111111111";
        const auto key_path = temporary.root() / "capability.key";
        REQUIRE(write_owner_file(
            key_path, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ));
        auto producer = glove::container::receipt_audit_producer::initialize({
            .key_path = key_path,
            .journal_path = temporary.root() / "capability-receipts.journal",
        });
        REQUIRE(producer.has_value());
        REQUIRE((*producer)->acknowledge_bootstrap((*producer)->anchor()).has_value());
        auto protocol = glove::control::receipt_audit_protocol::create(
            bootstrap_secret,
            *producer,
            shared_validator,
            shared_registry,
            concrete_runtime,
            {},
            materializations.string(),
            sealed
        );
        REQUIRE(protocol.has_value());
        const auto request_frame =
            std::string{"{\"jsonrpc\":\"2.0\",\"id\":\"capability\",\"method\":\"capabilities\","
                        "\"params\":{\"schema_version\":1,\"bootstrap_secret\":\""} +
            std::string{bootstrap_secret} + "\",\"deadline_ms\":2000,\"payload\":null}}";
        auto capability = (*protocol)->handle_frame(request_frame, 1'000);
        REQUIRE(capability.has_value());
        REQUIRE(
            capability->find("\"observation_intent_channel_schema_version\":1") != std::string::npos
        );

        auto runtime_mismatch_protocol = glove::control::receipt_audit_protocol::create(
            bootstrap_secret,
            *producer,
            shared_validator,
            shared_registry,
            {},
            {},
            materializations.string(),
            sealed
        );
        REQUIRE(runtime_mismatch_protocol.has_value());
        auto runtime_mismatch = (*runtime_mismatch_protocol)->handle_frame(request_frame, 1'000);
        REQUIRE(runtime_mismatch.has_value());
        REQUIRE(
            runtime_mismatch->find("\"observation_intent_channel_schema_version\":0") !=
            std::string::npos
        );

        auto other_registry_result = glove::control::session_registry::open_or_create(
            temporary.root() / "other-capability-sessions.journal",
            shared_validator,
            {},
            glove::control::default_session_registry_bytes,
            catalog
        );
        REQUIRE(other_registry_result.has_value());
        auto other_registry =
            std::shared_ptr<glove::control::session_registry>{std::move(*other_registry_result)};
        auto registry_mismatch_protocol = glove::control::receipt_audit_protocol::create(
            bootstrap_secret,
            *producer,
            shared_validator,
            other_registry,
            concrete_runtime,
            {},
            materializations.string(),
            sealed
        );
        REQUIRE(registry_mismatch_protocol.has_value());
        auto registry_mismatch = (*registry_mismatch_protocol)->handle_frame(request_frame, 1'000);
        REQUIRE(registry_mismatch.has_value());
        REQUIRE(
            registry_mismatch->find("\"observation_intent_channel_schema_version\":0") !=
            std::string::npos
        );

        REQUIRE(::chmod(endpoint.c_str(), 0660) == 0);
        REQUIRE(!sealed->operational_for(concrete_runtime.get(), shared_registry.get()));
        auto drifted_capability = (*protocol)->handle_frame(request_frame, 1'000);
        REQUIRE(drifted_capability.has_value());
        REQUIRE(
            drifted_capability->find("\"observation_intent_channel_schema_version\":0") !=
            std::string::npos
        );
        REQUIRE(::chmod(endpoint.c_str(), 0600) == 0);
        return 0;
    }

    REQUIRE(::chmod(endpoint.c_str(), 0660) == 0);
    REQUIRE(!(*factory)->operational());
    auto drift_error = (*factory)->prepare_session("mode-drift", "pi");
    REQUIRE(!drift_error.has_value());
    REQUIRE(drift_error.error().find(endpoint.string()) == std::string::npos);
    REQUIRE(drift_error.error().find("secret") == std::string::npos);
    REQUIRE(::chmod(endpoint.c_str(), 0600) == 0);
    REQUIRE((*factory)->operational());
    REQUIRE(::chmod(upstream.c_str(), 0755) == 0);
    REQUIRE(!(*factory)->operational());
    REQUIRE(::chmod(upstream.c_str(), 0700) == 0);
    REQUIRE((*factory)->operational());
    if (::geteuid() == 0) {
        REQUIRE(::chown(endpoint.c_str(), 1, 1) == 0);
        REQUIRE(!(*factory)->operational());
        REQUIRE(::chown(endpoint.c_str(), 0, 0) == 0);
        REQUIRE((*factory)->operational());
    }
    const auto extra_link = upstream / "extra-link.sock";
    REQUIRE(::link(endpoint.c_str(), extra_link.c_str()) == 0);
    REQUIRE(!(*factory)->operational());
    REQUIRE(::unlink(extra_link.c_str()) == 0);
    REQUIRE((*factory)->operational());

    // The mount descriptor is a detached open_tree clone, and Linux 6.12+
    // renders its /proc/self/fd readlink output as the mount root "/", not the
    // underlying path, so descriptor_path(mount_fd) cannot yield the session
    // directory here (and connect_mount already addresses the guest socket
    // through /proc/self/fd/N/alias instead). Resolve the session directory by
    // its exact staged name: prepare_session names it
    // "svc-<factory-generation>-<session-generation>-<session-id>", and the
    // only other staged directory under this runtime root belongs to
    // "generic-session", so the suffix below is unique.
    std::filesystem::path session_directory;
    for (const auto& entry : std::filesystem::directory_iterator{runtime}) {
        const auto name = entry.path().filename().string();
        if (entry.is_directory() && name.starts_with("svc-") && name.ends_with("-session-1")) {
            REQUIRE(session_directory.empty());
            session_directory = entry.path();
        }
    }
    REQUIRE(!session_directory.empty());
    const auto guest_socket = session_directory / "sage-observe";
    REQUIRE(::unlink(guest_socket.c_str()) == 0);
    std::ofstream{guest_socket} << "replacement";
    REQUIRE(std::filesystem::is_regular_file(guest_socket));
    client->reset();
    session->reset();
    mount_fd = unique_fd{};
    REQUIRE(std::filesystem::is_regular_file(guest_socket));
    std::filesystem::remove(guest_socket);
    std::filesystem::remove(session_directory);

    const auto descriptors_before = descriptor_count();
    auto leak_session = (*factory)->prepare_session("fd-check", "pi");
    REQUIRE(leak_session.has_value());
    auto leak_mount = (*leak_session)->mount();
    REQUIRE(leak_mount.has_value());
    REQUIRE(::close(leak_mount->descriptor_fd) == 0);
    leak_mount->descriptor_fd = -1;

#if !GLOVE_LOCAL_PROXY_TSAN
    const auto mount_fault_descriptors = descriptor_count();
    bool observed_mount_allocation_failure = false;
    bool observed_mount_success = false;
    for (std::int64_t fail_after = 0; fail_after < 8; ++fail_after) {
        allocation_fault::remaining.store(fail_after);
        try {
            auto mount_attempt = (*leak_session)->mount();
            allocation_fault::remaining.store(-1);
            if (mount_attempt) {
                REQUIRE(::close(mount_attempt->descriptor_fd) == 0);
                mount_attempt->descriptor_fd = -1;
                observed_mount_success = true;
            } else {
                observed_mount_allocation_failure = true;
            }
        } catch (...) {
            allocation_fault::remaining.store(-1);
            REQUIRE(false);
        }
        REQUIRE(descriptor_count() == mount_fault_descriptors);
    }
    REQUIRE(observed_mount_allocation_failure);
    REQUIRE(observed_mount_success);
#endif

    leak_session->reset();
    REQUIRE(descriptor_count() == descriptors_before);

#if !GLOVE_LOCAL_PROXY_TSAN
    const auto fault_entries = directory_entry_count(runtime);
    const auto fault_descriptors = descriptor_count();
    bool observed_late_allocation_failure = false;
    bool observed_success_after_failures = false;
    for (std::int64_t fail_after = 0; fail_after < 128; ++fail_after) {
        const auto fault_session_id = "allocation-fault-" + std::to_string(fail_after);
        bool failed = false;
        allocation_fault::remaining.store(fail_after);
        try {
            auto attempt = (*factory)->prepare_session(fault_session_id, "pi");
            allocation_fault::remaining.store(-1);
            failed = !attempt.has_value();
            if (attempt) {
                attempt->reset();
                observed_success_after_failures = true;
            }
        } catch (...) {
            allocation_fault::remaining.store(-1);
            std::fprintf(
                stderr,
                "allocation fault escaped expected at %lld\n",
                static_cast<long long>(fail_after)
            );
            REQUIRE(false);
        }
        allocation_fault::remaining.store(-1);
        observed_late_allocation_failure =
            observed_late_allocation_failure || (failed && fail_after >= 10);
        REQUIRE(directory_entry_count(runtime) == fault_entries);
        REQUIRE(descriptor_count() == fault_descriptors);
        if (observed_late_allocation_failure && observed_success_after_failures) {
            break;
        }
    }
    REQUIRE(observed_late_allocation_failure);
    REQUIRE(observed_success_after_failures);
#endif

    auto cancelled_session = (*factory)->prepare_session("cancelled", "pi");
    REQUIRE(cancelled_session.has_value());
    auto cancelled_mount = (*cancelled_session)->mount();
    REQUIRE(cancelled_mount.has_value());
    unique_fd cancelled_mount_fd{cancelled_mount->descriptor_fd};
    cancelled_mount->descriptor_fd = -1;
    unique_fd partial_client{connect_mount(cancelled_mount_fd.get(), "sage-observe")};
    REQUIRE(partial_client.get() >= 0);
    constexpr std::array<unsigned char, 2> partial_prefix{0, 0};
    REQUIRE(
        ::write(partial_client.get(), partial_prefix.data(), partial_prefix.size()) ==
        static_cast<ssize_t>(partial_prefix.size())
    );
    std::this_thread::sleep_for(std::chrono::milliseconds{20});
    const auto cancel_started = std::chrono::steady_clock::now();
    cancelled_session->reset();
    REQUIRE(std::chrono::steady_clock::now() - cancel_started < std::chrono::milliseconds{500});

    const auto symlink_parent = temporary.root() / "symlink-parent";
    REQUIRE(make_owner_directory(symlink_parent));
    const auto symlink_endpoint = symlink_parent / "service.sock";
    REQUIRE(::symlink(endpoint.c_str(), symlink_endpoint.c_str()) == 0);
    REQUIRE(!local_service_proxy_factory::create(
                 options_for(runtime, symlink_endpoint, audit, *adapter), shared_registry
    )
                 .has_value());

    const auto failed_registry_path = temporary.root() / "failed-sessions.journal";
    auto failed_registry = glove::control::session_registry::open_or_create(
        failed_registry_path,
        shared_validator,
        {},
        glove::control::default_session_registry_bytes,
        catalog
    );
    REQUIRE(failed_registry.has_value());
    auto failed_registry_shared =
        std::shared_ptr<glove::control::session_registry>{std::move(*failed_registry)};
    auto failing_audit = std::make_shared<rejecting_sink>();
    auto failing_factory = local_service_proxy_factory::create(
        options_for(runtime, endpoint, failing_audit, *adapter, 250), failed_registry_shared
    );
    REQUIRE(failing_factory.has_value());
    auto failing_session = (*failing_factory)->prepare_session("audit-failure", "pi");
    REQUIRE(failing_session.has_value());
    auto failing_mount = (*failing_session)->mount();
    REQUIRE(failing_mount.has_value());
    unique_fd failing_mount_fd{failing_mount->descriptor_fd};
    failing_mount->descriptor_fd = -1;
    std::atomic_bool failing_exact{false};
    auto failing_exchange =
        exchange_once(listener.get(), "secret-payload", "secret-response", failing_exact);
    auto failing_client = guest_channel_transport::adopt(
        connect_mount(failing_mount_fd.get(), "sage-observe"),
        16U * 1024U,
        static_cast<std::uint32_t>(::geteuid())
    );
    REQUIRE(failing_client.has_value());
    const auto failing_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    REQUIRE((*failing_client)->send_frame("secret-payload", failing_deadline).has_value());
    REQUIRE(!(*failing_client)->receive_frame(failing_deadline).has_value());
    failing_exchange.join();
    REQUIRE(failing_exact.load());
    std::weak_ptr<glove::control::session_registry> retained_registry = failed_registry_shared;
    failed_registry_shared.reset();
    REQUIRE(!retained_registry.expired());
    REQUIRE((*failing_factory)->operational());
    failing_client->reset();
    failing_session->reset();
    failing_factory->reset();
    REQUIRE(retained_registry.expired());

    listener = unique_fd{};
    // Replace the endpoint socket with a listener whose identity cannot equal
    // the recorded one: bind the replacement at a fresh path while the
    // original socket file still exists, then swap it in. Binding the
    // replacement only after unlinking can recycle the just-freed inode on
    // filesystems that reuse them, which would make the socket identity
    // comparison pass by ABA and defeat the drift expectation this section
    // asserts (docs/session-policy.md: pathname AF_UNIX does not exclude
    // same-UID ABA replacement).
    const auto replacement_socket = upstream / "replacement.sock";
    auto replacement_listener = make_listener(replacement_socket);
    REQUIRE(replacement_listener.get() >= 0);
    REQUIRE(::unlink(endpoint.c_str()) == 0);
    REQUIRE(::rename(replacement_socket.c_str(), endpoint.c_str()) == 0);
    REQUIRE(!(*factory)->operational());
    REQUIRE(!(*factory)->prepare_session("replaced", "pi").has_value());
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc == 1) {
        return run(false);
    }
    if (argc == 2 && std::string_view{argv[1]} == "--privileged") {
        return run(true);
    }
    return 1;
}
