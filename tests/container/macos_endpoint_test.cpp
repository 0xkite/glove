#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"
#include "glove/net/credentialed_endpoint.hpp"

#include "../support/descriptor_acl_fixture.hpp"
#include "runtime_filesystem.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class owned_fd {
public:
    explicit owned_fd(int fd = -1) noexcept : fd_{fd} {}

    owned_fd(const owned_fd&) = delete;
    auto operator=(const owned_fd&) -> owned_fd& = delete;

    owned_fd(owned_fd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}

    auto operator=(owned_fd&&) -> owned_fd& = delete;

    ~owned_fd() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return fd_; }

private:
    int fd_;
};

struct bound_socket {
    owned_fd fd;
    std::uint16_t port;
};

auto bind_socket(int family, std::string_view address, std::uint16_t port, bool udp = false)
    -> std::expected<bound_socket, std::string> {
    owned_fd fd{::socket(family, udp ? SOCK_DGRAM : SOCK_STREAM, 0)};
    if (fd.get() < 0) {
        return std::unexpected(std::string{"socket: "} + std::strerror(errno));
    }
    if (family == AF_INET6) {
        const int one = 1;
        if (::setsockopt(fd.get(), IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) != 0) {
            return std::unexpected(std::string{"IPV6_V6ONLY: "} + std::strerror(errno));
        }
    }
    const std::string address_owned{address};
    // The only casts are at the POSIX API boundary, with a live matching layout.
    const auto bind_address =
        [&fd](sockaddr* addr, socklen_t length) -> std::expected<void, std::string> {
        if (::bind(fd.get(), addr, length) != 0 || ::getsockname(fd.get(), addr, &length) != 0) {
            return std::unexpected(std::string{"fixture bind: "} + std::strerror(errno));
        }
        return {};
    };
    std::uint16_t bound_port = 0;
    if (family == AF_INET) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, address_owned.c_str(), &addr.sin_addr) != 1) {
            return std::unexpected("invalid IPv4 fixture address");
        }
        auto bound = bind_address(reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (!bound) {
            return std::unexpected(bound.error());
        }
        bound_port = ntohs(addr.sin_port);
    } else {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (::inet_pton(AF_INET6, address_owned.c_str(), &addr.sin6_addr) != 1) {
            return std::unexpected("invalid IPv6 fixture address");
        }
        auto bound = bind_address(reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (!bound) {
            return std::unexpected(bound.error());
        }
        bound_port = ntohs(addr.sin6_port);
    }
    if (!udp && ::listen(fd.get(), 16) != 0) {
        return std::unexpected(std::string{"fixture listen: "} + std::strerror(errno));
    }
    return bound_socket{std::move(fd), bound_port};
}

auto bind_neighbor(std::uint16_t port) -> std::expected<bound_socket, std::string> {
    if (port < 65535) {
        auto upper = bind_socket(AF_INET, "127.0.0.1", static_cast<std::uint16_t>(port + 1));
        if (upper) {
            return std::move(*upper);
        }
    }
    if (port > 1) {
        return bind_socket(AF_INET, "127.0.0.1", static_cast<std::uint16_t>(port - 1));
    }
    return std::unexpected("cannot reserve adjacent fixture port");
}

auto launch_probe(
    const glove::container::profile& profile,
    const std::string& probe,
    std::vector<std::string> arguments,
    bool pipes = false
) -> bool {
    arguments.insert(arguments.begin(), probe);
    if (!pipes) {
        auto code = glove::container::exec_contained(profile, arguments);
        if (!code) {
            std::fprintf(stderr, "exec probe: %s\n", code.error().c_str());
        }
        return code && *code == 0;
    }
    auto spawner = glove::container::make_default_spawner();
    auto started = spawner->spawn(profile, arguments);
    if (!started) {
        std::fprintf(stderr, "spawn probe: %s\n", started.error().c_str());
        return false;
    }
    auto handle = std::move(*started);
    auto line = handle->transport().recv();
    auto code = handle->wait();
    return line && *line == "probe-ok" && code && *code == 0;
}

auto make_endpoint(std::string nonce, std::atomic<unsigned>& forwarded)
    -> std::expected<std::unique_ptr<glove::net::credentialed_endpoint>, std::string> {
    glove::net::credentialed_endpoint_options options;
    options.endpoints.push_back({
        .provider = glove::net::endpoint_provider::anthropic,
        .path_prefix = "/anthropic",
        .upstream_host = "fixture.invalid",
        .upstream_port = 443,
        .secret_token = "fixture-host-only-secret",
        .session_nonce = std::move(nonce),
        .allowed_methods = {"POST"},
        .allowed_paths = {"/v1/messages"},
    });
    options.body_deadline_ms = 2000;
    options.response_deadline_ms = 2000;
    options.forward = [&forwarded](
                          const glove::net::upstream_request& request,
                          std::stop_token,
                          std::chrono::steady_clock::time_point
                      ) -> std::expected<glove::net::upstream_response, std::string> {
        if (request.secret_token != "fixture-host-only-secret" ||
            request.target != "/v1/messages" || request.body != "{}") {
            return std::unexpected("fixture forwarding mismatch");
        }
        for (const auto& [name, value] : request.headers) {
            (void)value;
            if (name == "x-api-key" || name == "authorization") {
                return std::unexpected("fixture nonce was forwarded");
            }
        }
        forwarded.fetch_add(1);
        return glove::net::upstream_response{
            .status_code = 200, .body = "fixture-response", .headers = {}
        };
    };
    return glove::net::start_credentialed_endpoint(std::move(options));
}

auto test_endpoint(const std::string& probe) -> int {
    std::atomic<unsigned> first_forwarded{0};
    std::atomic<unsigned> second_forwarded{0};
    auto first = make_endpoint("fixture-nonce-one", first_forwarded);
    REQUIRE(first);
    auto port = (*first)->port();
    // Reserve a real adjacent listener before a second endpoint can occupy it.
    // Both neighbors may already be bound or in TIME_WAIT; only fixture endpoint
    // allocation is retried, never a policy assertion or a denial probe.
    auto neighbor = [&]() -> std::expected<bound_socket, std::string> {
        for (unsigned attempt = 0; attempt <= 8U; ++attempt) {
            auto allocated = bind_neighbor(port);
            if (allocated || attempt == 8U) {
                return allocated;
            }
            first = make_endpoint("fixture-nonce-one", first_forwarded);
            if (!first) {
                return std::unexpected(first.error());
            }
            port = (*first)->port();
        }
        return std::unexpected("fixture allocation exceeded retry bound");
    }();
    if (!neighbor) {
        std::fprintf(stderr, "%s\n", neighbor.error().c_str());
    }
    REQUIRE(neighbor);
    const auto neighbor_port = neighbor->port;
    auto second = make_endpoint("fixture-nonce-two", second_forwarded);
    REQUIRE(second);
    const auto port_text = std::to_string(port);
    const auto other_port_text = std::to_string((*second)->port());
    REQUIRE(port != (*second)->port());

    // Real competing IPv6/UDP/neighbor listeners distinguish permission from reachability.
    // Darwin need not provision 127.0.0.2: its probe still requires EPERM/EACCES,
    // never a routing error, connection refusal, or timeout.
    auto ipv6 = bind_socket(AF_INET6, "::1", port);
    auto datagram = bind_socket(AF_INET, "127.0.0.1", port, true);
    REQUIRE(ipv6);
    REQUIRE(datagram);

    glove::container::profile offline;
    REQUIRE(launch_probe(offline, probe, {"connect", "4", "127.0.0.1", port_text, "deny"}));
    glove::container::profile allowed;
    allowed.bridge_endpoint = glove::container::bridge_endpoint_settings{.port = port};
    REQUIRE(launch_probe(allowed, probe, {"connect", "4", "127.0.0.1", port_text, "allow"}));
    REQUIRE(launch_probe(allowed, probe, {"connect", "4", "127.0.0.1", port_text, "allow"}, true));
    REQUIRE(launch_probe(
        allowed, probe, {"connect", "4", "127.0.0.1", std::to_string(neighbor_port), "deny"}
    ));
    REQUIRE(launch_probe(allowed, probe, {"connect", "4", "127.0.0.1", other_port_text, "deny"}));
    REQUIRE(launch_probe(allowed, probe, {"connect", "4", "127.0.0.2", port_text, "deny"}));
    REQUIRE(launch_probe(allowed, probe, {"connect", "6", "::1", port_text, "deny"}));
    REQUIRE(launch_probe(allowed, probe, {"connect", "6", "::ffff:127.0.0.1", port_text, "deny"}));
    REQUIRE(launch_probe(allowed, probe, {"udp", "4", "127.0.0.1", port_text, "deny"}));
    REQUIRE(launch_probe(allowed, probe, {"connect", "4", "192.0.2.1", port_text, "deny"}));
    REQUIRE(launch_probe(allowed, probe, {"connect", "4", "192.0.2.1", "443", "deny"}));
    REQUIRE(launch_probe(
        allowed, probe, {"http", "4", "127.0.0.1", port_text, "fixture-nonce-one", "200"}
    ));
    REQUIRE(launch_probe(
        allowed, probe, {"http", "4", "127.0.0.1", port_text, "fixture-nonce-two", "401"}, true
    ));
    auto second_profile = allowed;
    second_profile.bridge_endpoint->port = (*second)->port();
    REQUIRE(launch_probe(
        second_profile,
        probe,
        {"http", "4", "127.0.0.1", other_port_text, "fixture-nonce-two", "200"},
        true
    ));
    REQUIRE(launch_probe(
        second_profile,
        probe,
        {"http", "4", "127.0.0.1", other_port_text, "fixture-nonce-one", "401"}
    ));
    REQUIRE(first_forwarded.load() == 1);
    REQUIRE(second_forwarded.load() == 1);

    auto mixed = allowed;
    mixed.proxy = glove::container::proxy_settings{
        .port = (*second)->port(),
        .url = "http://glove:fixture@127.0.0.1:" + other_port_text,
    };
    REQUIRE(!glove::container::validate(mixed));
    REQUIRE(!glove::container::exec_contained(
        mixed, {probe, "connect", "4", "127.0.0.1", port_text, "allow"}
    ));
    auto spawner = glove::container::make_default_spawner();
    REQUIRE(!spawner->spawn(mixed, {probe, "connect", "4", "127.0.0.1", port_text, "allow"}));
    REQUIRE(!spawner->resource_capabilities().complete());
    REQUIRE(spawner->resource_capabilities().receipt_schema_version == 0);
    allowed.required_limits = glove::container::resource_limits{
        .cpu_time_ms = 1000,
        .memory_bytes = 67108864,
        .pids = 8,
        .wall_time_ms = 5000,
        .disk_bytes = 134217728,
        .terminal_output_bytes = 1048576,
    };
    REQUIRE(!glove::container::exec_contained(
        allowed, {probe, "connect", "4", "127.0.0.1", port_text, "allow"}
    ));
    REQUIRE(!spawner->spawn(allowed, {probe, "connect", "4", "127.0.0.1", port_text, "allow"}));
    return 0;
}

class temporary_tree {
public:
    temporary_tree() {
        char pattern[] = "/private/tmp/glove-macos-endpoint-XXXXXX";
        if (const auto* created = ::mkdtemp(pattern)) {
            path_ = created;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;
    temporary_tree(temporary_tree&&) = delete;
    auto operator=(temporary_tree&&) -> temporary_tree& = delete;

    ~temporary_tree() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto test_ancestor_churn() -> int {
    temporary_tree tree;
    REQUIRE(!tree.path().empty());
    std::error_code ec;
    const auto runtime = tree.path() / "runtime";
    std::filesystem::create_directory(runtime, ec);
    REQUIRE(!ec);
    for (int index = 0; index < 1024; ++index) {
        std::ofstream out{runtime / std::to_string(index)};
        out << "immutable-fixture";
        REQUIRE(out.good());
    }
    std::atomic<unsigned> mutations{0};
    std::atomic<bool> failed{false};
    const auto sibling = (tree.path() / "unrelated").string();
    std::jthread churn{[&](std::stop_token stop) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (!stop.stop_requested() && std::chrono::steady_clock::now() < deadline) {
            if (::mkdir(sibling.c_str(), 0700) != 0 || ::rmdir(sibling.c_str()) != 0) {
                failed.store(true);
                break;
            }
            mutations.fetch_add(1);
        }
    }};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (mutations.load() == 0 && !failed.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    const auto before = mutations.load();
    auto admitted = glove::container::macos_detail::validate_runtime_filesystem(
        {{.path = runtime.string(), .writable = false}}
    );
    const auto after = mutations.load();
    churn.request_stop();
    churn.join();
    REQUIRE(!failed.load());
    REQUIRE(before > 0 && after > before);
    if (!admitted) {
        std::fprintf(stderr, "ancestor churn: %s\n", admitted.error().c_str());
    }
    REQUIRE(admitted);
    return 0;
}

auto test_filesystem(const std::string& probe) -> int {
    temporary_tree tree;
    REQUIRE(!tree.path().empty());
    std::error_code ec;
    const auto runtime = tree.path() / "runtime";
    const auto outside = tree.path() / "operator-auth-fixture";
    const auto workspace = tree.path() / "workspace";
    std::filesystem::create_directory(workspace, ec);
    REQUIRE(!ec);
    std::filesystem::create_directory(runtime, ec);
    REQUIRE(!ec);
    {
        std::ofstream out{runtime / "resource"};
        out << "fixture-runtime";
        REQUIRE(out.good());
    }
    {
        std::ofstream out{outside};
        out << "fixture-outside";
        REQUIRE(out.good());
    }
    const auto resource = (runtime / "resource").string();
    glove::container::profile profile;
    profile.runtime_filesystem.push_back({.path = runtime.string(), .writable = false});
    profile.filesystem.push_back({.path = workspace.string(), .writable = true});
    REQUIRE(launch_probe(profile, probe, {"fs", resource, "read"}));
    REQUIRE(launch_probe(profile, probe, {"fs", resource, "read"}, true));
    REQUIRE(launch_probe(profile, probe, {"fs", resource, "deny-write"}));
    REQUIRE(launch_probe(profile, probe, {"fs", outside.string(), "deny-read"}, true));
    struct stat baseline{};
    REQUIRE(::lstat(resource.c_str(), &baseline) == 0);
    const auto unchanged = [&]() {
        struct stat after{};
        if (::lstat(resource.c_str(), &after) != 0) {
            return false;
        }
        std::ifstream in{resource};
        const std::string contents{std::istreambuf_iterator<char>{in}, {}};
        return in.good() && contents == "fixture-runtime" && after.st_dev == baseline.st_dev &&
               after.st_ino == baseline.st_ino && after.st_uid == baseline.st_uid &&
               after.st_gid == baseline.st_gid && after.st_mode == baseline.st_mode &&
               after.st_nlink == baseline.st_nlink && after.st_size == baseline.st_size &&
               after.st_mtimespec.tv_sec == baseline.st_mtimespec.tv_sec &&
               after.st_mtimespec.tv_nsec == baseline.st_mtimespec.tv_nsec &&
               after.st_ctimespec.tv_sec == baseline.st_ctimespec.tv_sec &&
               after.st_ctimespec.tv_nsec == baseline.st_ctimespec.tv_nsec;
    };
    const auto alias = (workspace / "alias").string();
    for (const bool pipes : {false, true}) {
        const auto marker = (workspace / (pipes ? "spawn-marker" : "exec-marker")).string();
        REQUIRE(launch_probe(profile, probe, {"mutate", "create", marker, marker, "allow"}, pipes));
        REQUIRE(std::filesystem::file_size(marker) == 1);
        for (const auto* action : {"write", "chmod", "unlink", "rename", "map", "link"}) {
            REQUIRE(
                launch_probe(profile, probe, {"mutate", action, resource, alias, "deny"}, pipes)
            );
            REQUIRE(unchanged());
            REQUIRE(!std::filesystem::exists(alias));
        }
    }
    const auto rejected_before_launch = [&](std::string_view expected,
                                            const std::vector<std::string>& arguments) {
        std::vector<std::string> argv{probe};
        argv.insert(argv.end(), arguments.begin(), arguments.end());
        auto code = glove::container::exec_contained(profile, argv);
        if (code || code.error().find(expected) == std::string::npos) {
            return false;
        }
        auto spawner = glove::container::make_default_spawner();
        auto started = spawner->spawn(profile, argv);
        return !started && started.error().find(expected) != std::string::npos;
    };
    // A pre-existing alias must not turn a read-only runtime grant into write authority.
    REQUIRE(::link(resource.c_str(), alias.c_str()) == 0);
    REQUIRE(::lstat(resource.c_str(), &baseline) == 0);
    for (const auto* action : {"write", "chmod", "map"}) {
        REQUIRE(rejected_before_launch("single-link", {"mutate", action, alias, alias, "deny"}));
        REQUIRE(unchanged());
    }
    REQUIRE(::unlink(alias.c_str()) == 0);
    REQUIRE(::lstat(resource.c_str(), &baseline) == 0);
    const auto nested = runtime / "nested";
    std::filesystem::create_directory(nested, ec);
    REQUIRE(!ec);
    // Relative parent components are safe only after their preceding symlinks resolve.
    std::filesystem::create_symlink("../resource", nested / "resource-link", ec);
    REQUIRE(!ec);
    std::filesystem::create_symlink("nested", runtime / "dir-link", ec);
    REQUIRE(!ec);
    for (const bool pipes : {false, true}) {
        REQUIRE(launch_probe(
            profile,
            probe,
            {"fs", (runtime / "dir-link/resource-link").string(), "read-link"},
            pipes
        ));
    }
    for (int hop = 1; hop <= 32; ++hop) {
        std::filesystem::create_symlink(
            hop == 1 ? "resource" : "chain-" + std::to_string(hop - 1),
            runtime / ("chain-" + std::to_string(hop)),
            ec
        );
        REQUIRE(!ec);
    }
    for (const bool pipes : {false, true}) {
        // Admission handles 32 hops; use a short chain for the kernel's own link limit.
        REQUIRE(
            launch_probe(profile, probe, {"fs", (runtime / "chain-2").string(), "read-link"}, pipes)
        );
    }
    const auto bad = runtime / "bad";
    for (const auto& target :
         {std::string{"missing"},
          std::string{"bad"},
          outside.string(),
          std::string{"../workspace/exec-marker"},
          std::string{"chain-32"}}) {
        std::filesystem::create_symlink(target, bad, ec);
        REQUIRE(!ec);
        REQUIRE(rejected_before_launch("runtime filesystem", {"fs", resource, "read"}));
        REQUIRE(std::filesystem::remove(bad, ec));
        REQUIRE(!ec);
        REQUIRE(unchanged());
    }
    REQUIRE(::mkfifo(bad.c_str(), 0600) == 0);
    REQUIRE(rejected_before_launch("runtime filesystem", {"fs", resource, "read"}));
    REQUIRE(::unlink(bad.c_str()) == 0);
    auto deep = runtime;
    for (int depth = 0; depth < 129; ++depth) {
        deep /= "d";
        std::filesystem::create_directory(deep, ec);
        REQUIRE(!ec);
    }
    // Payload traversal permits depth129 (source128 plus one root-N wrapper),
    // including a link to the deepest empty directory; depth130 still rejects.
    std::filesystem::create_symlink(
        std::filesystem::relative(deep, runtime), runtime / "deep-safe", ec
    );
    REQUIRE(!ec);
    REQUIRE(
        glove::container::macos_detail::validate_runtime_filesystem(profile.runtime_filesystem)
    );
    deep /= "d";
    REQUIRE(std::filesystem::create_directory(deep, ec) && !ec);
    REQUIRE(rejected_before_launch("runtime filesystem", {"fs", resource, "read"}));
    REQUIRE(unchanged());
    auto unsafe = profile;
    unsafe.runtime_filesystem.front().writable = true;
    REQUIRE(!glove::container::validate(unsafe));
    auto broad = profile;
    broad.runtime_filesystem.front().path = "/";
    REQUIRE(!glove::container::validate(broad));
    return 0;
}

auto test_acl_admission(const std::string& probe) -> int {
    temporary_tree tree;
    REQUIRE(!tree.path().empty());
    const auto agent = tree.path() / "agent";
    const auto workspace = tree.path() / "workspace";
    const auto runtime = tree.path() / "runtime";
    const auto nested = runtime / "nested";
    REQUIRE(::mkdir(agent.c_str(), 0700) == 0);
    REQUIRE(::mkdir(workspace.c_str(), 0700) == 0);
    REQUIRE(::mkdir(runtime.c_str(), 0700) == 0);
    REQUIRE(::mkdir(nested.c_str(), 0700) == 0);
    const auto authority = agent / "models.json";
    const auto payload = nested / "payload";
    for (const auto& file : {authority, payload}) {
        std::ofstream output{file};
        output << "fixture-authority";
        REQUIRE(output.good());
    }
    REQUIRE(::chmod(authority.c_str(), 0600) == 0);
    REQUIRE(::chmod(payload.c_str(), 0400) == 0);
    const auto link = nested / "alias";
    REQUIRE(::symlink("payload", link.c_str()) == 0);
    REQUIRE(::chmod(nested.c_str(), 0500) == 0);
    REQUIRE(::chmod(runtime.c_str(), 0500) == 0);
    glove::container::profile profile;
    profile.filesystem = {
        {.path = agent.string(), .writable = true}, {.path = workspace.string(), .writable = true}
    };
    profile.runtime_filesystem = {{.path = runtime.string(), .writable = false}};
    profile.immutable_files = {authority.string()};
    profile.reserved_entries = {{.parent = workspace.string(), .name = ".pi"}};
    const auto accepted = [&]() {
        return glove::container::macos_detail::validate_runtime_filesystem(
                   profile.runtime_filesystem
               ) &&
               glove::container::macos_detail::validate_launch_constraints(profile);
    };
    const auto rejected = [&]() {
        const std::vector<std::string> argv{probe, "fs", authority.string(), "read"};
        auto executed = glove::container::exec_contained(profile, argv);
        auto spawner = glove::container::make_default_spawner();
        auto spawned = spawner->spawn(profile, argv);
        return !executed && executed.error().contains("ACL") && !spawned &&
               spawned.error().contains("ACL");
    };
    REQUIRE(accepted());
    REQUIRE(glove::test::set_fixture_acl(authority, false, ACL_EXTENDED_ALLOW, true));
    REQUIRE(rejected());
    REQUIRE(glove::test::set_fixture_acl(authority, false, ACL_EXTENDED_DENY));
    REQUIRE(accepted());
    REQUIRE(glove::test::set_fixture_acl(agent, true, ACL_EXTENDED_ALLOW, true));
    REQUIRE(rejected());
    REQUIRE(glove::test::set_fixture_acl(agent, true, ACL_EXTENDED_DENY));
    REQUIRE(accepted());
    REQUIRE(glove::test::set_fixture_acl(runtime, true, ACL_EXTENDED_ALLOW, true));
    REQUIRE(accepted());
    for (const auto& target : {payload, nested, workspace, tree.path()}) {
        REQUIRE(glove::test::set_fixture_acl(target, target != payload));
        REQUIRE(rejected());
        REQUIRE(glove::test::set_fixture_acl(target, target != payload, ACL_EXTENDED_ALLOW, true));
        REQUIRE(accepted());
    }
    REQUIRE(glove::test::set_fixture_acl(link, false, ACL_EXTENDED_ALLOW, false, true));
    REQUIRE(rejected());
    REQUIRE(glove::test::set_fixture_acl(link, false, ACL_EXTENDED_ALLOW, true, true));
    REQUIRE(accepted());
    REQUIRE(glove::test::set_fixture_acl(link, false, ACL_EXTENDED_DENY, false, true));
    REQUIRE(accepted());
    struct stat info{};
    REQUIRE(::lstat(authority.c_str(), &info) == 0 && (info.st_mode & 07777U) == 0600U);
    REQUIRE(::lstat(payload.c_str(), &info) == 0 && (info.st_mode & 07777U) == 0400U);
    REQUIRE(::lstat(nested.c_str(), &info) == 0 && (info.st_mode & 07777U) == 0500U);
    return 0;
}

auto test_configuration(const std::string& probe) -> int {
    temporary_tree tree;
    REQUIRE(!tree.path().empty());
    const auto agent = tree.path() / "agent";
    const auto workspace = tree.path() / "workspace.[x]+\"";
    REQUIRE(::mkdir(agent.c_str(), 0700) == 0);
    REQUIRE(::mkdir(workspace.c_str(), 0700) == 0);
    const auto authority = (agent / "models.json").string();
    {
        std::ofstream out{authority};
        out << "fixture-authority";
        REQUIRE(out.good());
    }
    REQUIRE(::chmod(authority.c_str(), 0600) == 0);
    const auto alias = (workspace / "alias").string();
    glove::container::profile profile;
    profile.filesystem = {
        {.path = agent.string(), .writable = true}, {.path = workspace.string(), .writable = true}
    };
    profile.immutable_files = {authority};
    profile.reserved_entries = {{.parent = workspace.string(), .name = ".pi"}};
    struct stat baseline{};
    REQUIRE(::lstat(authority.c_str(), &baseline) == 0);
    const auto unchanged = [&]() {
        struct stat after{};
        if (::lstat(authority.c_str(), &after) != 0) {
            return false;
        }
        std::ifstream in{authority};
        const std::string contents{std::istreambuf_iterator<char>{in}, {}};
        return in.good() && contents == "fixture-authority" && after.st_ino == baseline.st_ino &&
               after.st_dev == baseline.st_dev && after.st_mode == baseline.st_mode &&
               after.st_nlink == baseline.st_nlink && after.st_size == baseline.st_size &&
               after.st_mtimespec.tv_sec == baseline.st_mtimespec.tv_sec &&
               after.st_mtimespec.tv_nsec == baseline.st_mtimespec.tv_nsec &&
               after.st_ctimespec.tv_sec == baseline.st_ctimespec.tv_sec &&
               after.st_ctimespec.tv_nsec == baseline.st_ctimespec.tv_nsec;
    };
    for (const bool pipes : {false, true}) {
        REQUIRE(launch_probe(profile, probe, {"fs", authority, "read"}, pipes));
        const auto lock = (agent / (pipes ? "spawn.lock" : "exec.lock")).string();
        REQUIRE(launch_probe(profile, probe, {"mutate", "mkdir", lock, lock, "allow"}, pipes));
        REQUIRE(launch_probe(
            profile, probe, {"mutate", "create", lock + "/owner", lock, "allow"}, pipes
        ));
        for (const auto* action : {"write", "chmod", "unlink", "rename", "map", "link"}) {
            REQUIRE(
                launch_probe(profile, probe, {"mutate", action, authority, alias, "deny"}, pipes)
            );
            REQUIRE(unchanged());
            REQUIRE(!std::filesystem::exists(alias));
        }
        REQUIRE(::symlink(authority.c_str(), alias.c_str()) == 0);
        for (const auto* action : {"follow-write", "chmod", "follow-map"}) {
            REQUIRE(launch_probe(profile, probe, {"mutate", action, alias, alias, "deny"}, pipes));
            REQUIRE(unchanged());
        }
        REQUIRE(::unlink(alias.c_str()) == 0);
        REQUIRE(
            launch_probe(profile, probe, {"mutate", "rename", agent.string(), alias, "deny"}, pipes)
        );
        REQUIRE(
            launch_probe(profile, probe, {"mutate", "chmod", agent.string(), alias, "deny"}, pipes)
        );
        REQUIRE(launch_probe(
            profile,
            probe,
            {"mutate", "rename", workspace.string(), (agent / "moved-workspace").string(), "deny"},
            pipes
        ));
        REQUIRE(launch_probe(
            profile, probe, {"mutate", "chmod", workspace.string(), alias, "deny"}, pipes
        ));
        const auto dir = (workspace / (pipes ? "spawn-dir" : "exec-dir")).string();
        REQUIRE(::mkdir(dir.c_str(), 0700) == 0);
        for (const auto* name : {".pi", ".PI", ".pI"}) {
            const auto reserved = (workspace / name).string();
            REQUIRE(
                launch_probe(profile, probe, {"mutate", "mkdir", reserved, reserved, "deny"}, pipes)
            );
            REQUIRE(
                launch_probe(profile, probe, {"mutate", "symlink", dir, reserved, "deny"}, pipes)
            );
            REQUIRE(
                launch_probe(profile, probe, {"mutate", "rename", dir, reserved, "deny"}, pipes)
            );
            REQUIRE(!std::filesystem::exists(reserved));
            REQUIRE(std::filesystem::is_directory(dir));
        }
    }
    const auto rejected = [&](std::string_view reason) {
        const std::vector<std::string> argv{probe, "fs", authority, "read"};
        auto code = glove::container::exec_contained(profile, argv);
        if (code || code.error().find(reason) == std::string::npos) {
            return false;
        }
        auto spawner = glove::container::make_default_spawner();
        auto started = spawner->spawn(profile, argv);
        return !started && started.error().find(reason) != std::string::npos;
    };
    REQUIRE(::link(authority.c_str(), alias.c_str()) == 0);
    REQUIRE(rejected("single-link"));
    REQUIRE(::unlink(alias.c_str()) == 0);
    const auto reserved = (workspace / ".pi").string();
    REQUIRE(::symlink("exec-dir", reserved.c_str()) == 0);
    REQUIRE(rejected("reserved"));
    REQUIRE(::unlink(reserved.c_str()) == 0);
    REQUIRE(::mkdir(reserved.c_str(), 0700) == 0);
    REQUIRE(rejected("reserved"));
    REQUIRE(::rmdir(reserved.c_str()) == 0);
    const auto case_alias = (workspace / ".PI").string();
    REQUIRE(::mkdir(case_alias.c_str(), 0700) == 0);
    REQUIRE(rejected("reserved"));
    REQUIRE(::rmdir(case_alias.c_str()) == 0);
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (argc != 3) {
        return 2;
    }
    const std::string probe{argv[2]};
    const std::string_view mode{argv[1]};
    if (mode == "--endpoint") {
        return test_endpoint(probe);
    }
    if (mode == "--configuration") {
        if (auto code = test_acl_admission(probe); code != 0) {
            return code;
        }
        return test_configuration(probe);
    }
    if (mode == "--filesystem") {
        if (auto code = test_ancestor_churn(); code != 0) {
            return code;
        }
        return test_filesystem(probe);
    }
    return 2;
}
