// macOS spawner. Arbitrary agents are launched through sandbox-exec with a
// deny-default SBPL profile before their first instruction.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/mcp/transport.hpp"

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::container {

namespace {

constexpr std::size_t recv_chunk_bytes = 4096;

// Hard ceiling on a single newline-framed frame so a peer that never sends a
// newline cannot grow this buffer without bound and OOM the host.
constexpr std::size_t max_frame_bytes = 16U * 1024U * 1024U;

// One-direction newline-framed pipe transport, mirroring stdio_transport but
// owned by the spawner so the same fds drive both directions. (The kernel
// transport interface is duplex.)
class pipe_transport final : public glove::mcp::transport {
public:
    pipe_transport(int write_fd, int read_fd) : write_fd_{write_fd}, read_fd_{read_fd} {}

    pipe_transport(const pipe_transport&) = delete;
    pipe_transport& operator=(const pipe_transport&) = delete;
    pipe_transport(pipe_transport&&) = delete;
    pipe_transport& operator=(pipe_transport&&) = delete;

    ~pipe_transport() override {
        if (write_fd_ >= 0) {
            ::close(write_fd_);
        }
        if (read_fd_ >= 0) {
            ::close(read_fd_);
        }
    }

    auto send(std::string_view frame) -> std::expected<void, std::string> override {
        std::string line;
        line.reserve(frame.size() + 1);
        line.append(frame);
        line.push_back('\n');
        const char* cursor = line.data();
        std::size_t remaining = line.size();
        while (remaining > 0) {
            ::ssize_t written = ::write(write_fd_, cursor, remaining);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"write: "} + std::strerror(errno));
            }
            cursor += written;
            remaining -= static_cast<std::size_t>(written);
        }
        return {};
    }

    auto recv() -> std::expected<std::string, std::string> override {
        for (;;) {
            auto nl = buffer_.find('\n');
            if (nl != std::string::npos) {
                std::string out = buffer_.substr(0, nl);
                buffer_.erase(0, nl + 1);
                return out;
            }
            std::array<char, recv_chunk_bytes> chunk{};
            const ::ssize_t got = ::read(read_fd_, chunk.data(), chunk.size());
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"read: "} + std::strerror(errno));
            }
            if (got == 0) {
                return std::unexpected(std::string{"unexpected eof from agent"});
            }
            if (buffer_.size() + static_cast<std::size_t>(got) > max_frame_bytes) {
                return std::unexpected(std::string{"frame exceeds max_frame_bytes"});
            }
            buffer_.append(chunk.data(), static_cast<std::size_t>(got));
        }
    }

    void release_ownership() {
        write_fd_ = -1;
        read_fd_ = -1;
    }

private:
    int write_fd_;
    int read_fd_;
    std::string buffer_;
};

class macos_agent_handle final : public agent_handle {
public:
    macos_agent_handle(::pid_t pid, std::unique_ptr<pipe_transport> t)
        : pid_{pid}, transport_{std::move(t)} {}

    ~macos_agent_handle() override {
        transport_.reset();
        if (!waited_) {
            (void)wait();
        }
    }

    auto transport() -> glove::mcp::transport& override { return *transport_; }

    auto wait() -> std::expected<int, std::string> override {
        if (waited_) {
            return cached_code_;
        }
        int status = 0;
        for (int spins = 0; spins < 50; ++spins) {
            ::pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_) {
                (void)::kill(-pid_, SIGKILL);
                waited_ = true;
                cached_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                return cached_code_;
            }
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
            }
            ::usleep(10 * 1000);
        }
        (void)::kill(-pid_, SIGTERM);
        for (int spins = 0; spins < 50; ++spins) {
            ::pid_t r = ::waitpid(pid_, &status, WNOHANG);
            if (r == pid_) {
                (void)::kill(-pid_, SIGKILL);
                waited_ = true;
                cached_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
                return cached_code_;
            }
            if (r < 0 && errno != EINTR) {
                return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
            }
            ::usleep(10 * 1000);
        }
        (void)::kill(-pid_, SIGKILL);
        while (::waitpid(pid_, &status, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
        }
        waited_ = true;
        cached_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return cached_code_;
    }

    [[nodiscard]] auto resource_receipt() const
        -> std::expected<resource_enforcement_receipt, std::string> override {
        return std::unexpected(std::string{"resource enforcement receipt unavailable"});
    }

private:
    ::pid_t pid_;
    std::unique_ptr<pipe_transport> transport_;
    bool waited_ = false;
    int cached_code_ = -1;
};

void close_pipe_pair(int (&fds)[2]) {
    if (fds[0] >= 0) {
        ::close(fds[0]);
    }
    if (fds[1] >= 0) {
        ::close(fds[1]);
    }
}

// Escape a host path for inclusion in an SBPL string literal.
auto sbpl_escape(std::string_view s) -> std::string {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return out;
}

auto resolve_program(const profile& prof, std::string_view program)
    -> std::expected<std::string, std::string> {
    std::vector<std::filesystem::path> candidates;
    if (program.find('/') != std::string_view::npos) {
        candidates.emplace_back(program);
    } else {
        std::string path = "/usr/bin:/bin:/usr/sbin:/sbin";
        for (const auto& entry : prof.environment) {
            if (entry.starts_with("PATH=")) {
                path = entry.substr(5);
                break;
            }
        }
        std::string_view remaining{path};
        while (true) {
            const auto colon = remaining.find(':');
            const auto part = remaining.substr(0, colon);
            if (!part.empty()) {
                candidates.emplace_back(std::filesystem::path{part} / program);
            }
            if (colon == std::string_view::npos) {
                break;
            }
            remaining.remove_prefix(colon + 1);
        }
    }
    for (const auto& candidate : candidates) {
        if (::access(candidate.c_str(), X_OK) != 0) {
            continue;
        }
        std::error_code ec;
        auto canonical = std::filesystem::canonical(candidate, ec);
        if (!ec) {
            return canonical.string();
        }
    }
    return std::unexpected(std::string{"cannot resolve executable: "} + std::string{program});
}

void append_read_rule(std::string& policy, std::string_view path) {
    policy += "(allow file-read* (literal \"";
    policy += sbpl_escape(path);
    policy += "\") (subpath \"";
    policy += sbpl_escape(path);
    policy += "\"))\n";
}

void append_parent_metadata_rules(std::string& policy, std::string_view path) {
    std::filesystem::path current{path};
    current = current.parent_path();
    while (!current.empty() && current != current.root_path()) {
        policy += "(allow file-read-metadata (literal \"";
        policy += sbpl_escape(current.string());
        policy += "\"))\n";
        current = current.parent_path();
    }
}

// system.sb provides the platform's dynamic-loader and Mach-service plumbing.
// Glove adds only immutable command/runtime directories, the selected agent
// executable, and the operator's explicit filesystem grants.
auto generate_sbpl(const profile& prof, std::string_view agent_program) -> std::string {
    std::string p = "(version 1)\n(deny default)\n(import \"system.sb\")\n";
    p += "(allow process-exec*)\n(allow process-fork)\n(allow sysctl-read)\n";
    for (const auto* runtime : {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}) {
        append_read_rule(p, runtime);
    }
    append_read_rule(p, "/private/var/select");
    append_read_rule(p, agent_program);
    append_parent_metadata_rules(p, agent_program);
#if defined(GLOVE_SANITIZER_RUNTIME_PATH)
    append_read_rule(p, GLOVE_SANITIZER_RUNTIME_PATH);
    append_parent_metadata_rules(p, GLOVE_SANITIZER_RUNTIME_PATH);
#endif
    for (const auto& rule : prof.filesystem) {
        append_read_rule(p, rule.path);
        append_parent_metadata_rules(p, rule.path);
    }
    p += "(deny network*)\n";
    if (prof.proxy) {
        p += "(allow network-outbound (remote ip \"localhost:";
        p += std::to_string(prof.proxy->port);
        p += "\"))\n";
    }
    p += "(deny file-write*)\n";
    for (const auto& rule : prof.filesystem) {
        if (rule.writable) {
            p += "(allow file-write* (literal \"";
            p += sbpl_escape(rule.path);
            p += "\") (subpath \"";
            p += sbpl_escape(rule.path);
            p += "\"))\n";
        }
    }
    return p;
}

// Wrap the agent in `sandbox-exec -p <profile>` so an arbitrary, non-glove-aware
// binary (node, python, a real coding agent) is contained by an OS-enforced
// SBPL profile applied before its first instruction — not left to self-sandbox
// the way the synthetic agent does. sandbox-exec compiles + applies the
// profile, then exec()s the target.
auto sandboxed_argv(
    const profile& prof, const std::vector<std::string>& argv, std::string resolved_program
) -> std::vector<std::string> {
    std::vector<std::string> out;
    out.reserve(argv.size() + 3);
    out.emplace_back("/usr/bin/sandbox-exec");
    out.emplace_back("-p");
    out.emplace_back(generate_sbpl(prof, resolved_program));
    out.emplace_back(std::move(resolved_program));
    for (std::size_t i = 1; i < argv.size(); ++i) {
        out.push_back(argv[i]);
    }
    return out;
}

auto has_environment_name(const std::vector<std::string>& environment, std::string_view name)
    -> bool {
    return std::any_of(environment.begin(), environment.end(), [name](const std::string& entry) {
        return entry.size() > name.size() && entry[name.size()] == '=' && entry.starts_with(name);
    });
}

auto sandboxed_env(const profile& prof) -> std::vector<std::string> {
    std::vector<std::string> env = prof.environment;
    if (!has_environment_name(env, "PATH")) {
        env.emplace_back("PATH=/usr/bin:/bin:/usr/sbin:/sbin");
    }
    if (prof.home_dir) {
        env.emplace_back("HOME=" + *prof.home_dir);
    }
    if (prof.temp_dir) {
        env.emplace_back("TMPDIR=" + *prof.temp_dir);
    }
    env.emplace_back("GLOVE_SANDBOXED=1");
    if (prof.proxy) {
        for (const auto* key :
             {"HTTPS_PROXY=", "https_proxy=", "HTTP_PROXY=", "http_proxy=", "ALL_PROXY="}) {
            env.emplace_back(std::string{key} + prof.proxy->url);
        }
    }
    return env;
}

// Synchronously run argv contained, with the parent's stdio (0/1/2) inherited —
// no MCP pipe, no kernel. Blocks until the agent exits; returns its code. Used
// by `glove exec` for a real, self-driving agent (its terminal + LLM are its
// own; glove is the perimeter + egress, not an MCP counterparty).
auto exec_passthrough(const profile& prof, const std::vector<std::string>& argv)
    -> std::expected<int, std::string> {
    if (argv.empty()) {
        return std::unexpected(std::string{"spawner: empty argv"});
    }
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (checked->bridge_endpoint) {
        return std::unexpected(
            std::string{"bridge_endpoint is not implemented on the macOS backend"}
        );
    }
    const auto& effective = *checked;
    auto resolved = resolve_program(effective, argv.front());
    if (!resolved) {
        return std::unexpected(resolved.error());
    }
    ::posix_spawn_file_actions_t actions{};
    if (int rc = ::posix_spawn_file_actions_init(&actions); rc != 0) {
        return std::unexpected(std::string{"file_actions_init: "} + std::strerror(rc));
    }
    // CLOEXEC_DEFAULT closes everything; explicitly keep stdio so the agent
    // owns its terminal while no other host fd leaks in.
    ::posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO);
    ::posix_spawn_file_actions_addinherit_np(&actions, STDOUT_FILENO);
    ::posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO);
    // Start in the workspace so a coding agent operates on the project. The
    // `_np` form is the one present across macOS versions (10.15+); macOS 26
    // deprecates it in favour of the unsuffixed name, which older systems lack.
    const auto& start_dir = effective.work_dir ? effective.work_dir : effective.home_dir;
    if (start_dir && !start_dir->empty()) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        ::posix_spawn_file_actions_addchdir_np(&actions, start_dir->c_str());
#pragma clang diagnostic pop
    }

    ::posix_spawnattr_t attr{};
    if (int rc = ::posix_spawnattr_init(&attr); rc != 0) {
        ::posix_spawn_file_actions_destroy(&actions);
        return std::unexpected(std::string{"spawnattr_init: "} + std::strerror(rc));
    }
    ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);

    std::vector<std::string> argv_owned = sandboxed_argv(effective, argv, std::move(*resolved));
    std::vector<std::string> env_owned = sandboxed_env(effective);
    std::vector<char*> argv_ptrs;
    std::vector<char*> envp;
    argv_ptrs.reserve(argv_owned.size() + 1);
    envp.reserve(env_owned.size() + 1);
    for (auto& a : argv_owned) {
        argv_ptrs.push_back(a.data());
    }
    argv_ptrs.push_back(nullptr);
    for (auto& e : env_owned) {
        envp.push_back(e.data());
    }
    envp.push_back(nullptr);

    ::pid_t pid = -1;
    const int rc =
        ::posix_spawnp(&pid, argv_owned[0].c_str(), &actions, &attr, argv_ptrs.data(), envp.data());
    ::posix_spawn_file_actions_destroy(&actions);
    ::posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        return std::unexpected(std::string{"posix_spawnp: "} + std::strerror(rc));
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(std::string{"waitpid: "} + std::strerror(errno));
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

auto macos_resource_capabilities() noexcept -> resource_enforcement_capabilities {
    // Partial rlimits are not advertised as remote-session safety. All limits
    // and their receipts must ship together before this changes.
    return {};
}

class macos_spawner final : public spawner {
public:
    [[nodiscard]] auto resource_capabilities() const noexcept
        -> resource_enforcement_capabilities override {
        return macos_resource_capabilities();
    }

    auto spawn(const profile& prof, const std::vector<std::string>& argv)
        -> std::expected<std::unique_ptr<agent_handle>, std::string> override {
        if (argv.empty()) {
            return std::unexpected(std::string{"spawner: empty argv"});
        }
        auto checked = validate(prof);
        if (!checked) {
            return std::unexpected(std::string{"profile: "} + checked.error());
        }
        // The macOS backend has no private-loopback descriptor bridge, so a
        // profile that names a reverse endpoint cannot reach it. Reject at every
        // entry point rather than launch an agent that silently cannot
        // authenticate.
        if (checked->bridge_endpoint) {
            return std::unexpected(
                std::string{"bridge_endpoint is not implemented on the macOS backend"}
            );
        }
        if (auto limits = require_resource_enforcement(*checked, resource_capabilities());
            !limits) {
            return std::unexpected(limits.error());
        }
        const auto& effective = *checked;
        auto resolved = resolve_program(effective, argv.front());
        if (!resolved) {
            return std::unexpected(resolved.error());
        }

        // Two pipes: pipe_in carries parent→child (child stdin); pipe_out
        // carries child→parent (child stdout). Child stderr is inherited so
        // diagnostics surface during dev.
        int pipe_in[2] = {-1, -1};
        int pipe_out[2] = {-1, -1};
        if (::pipe(pipe_in) != 0) {
            return std::unexpected(std::string{"pipe(in): "} + std::strerror(errno));
        }
        if (::pipe(pipe_out) != 0) {
            const int saved = errno;
            close_pipe_pair(pipe_in);
            return std::unexpected(std::string{"pipe(out): "} + std::strerror(saved));
        }

        ::posix_spawn_file_actions_t actions{};
        if (int rc = ::posix_spawn_file_actions_init(&actions); rc != 0) {
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"file_actions_init: "} + std::strerror(rc));
        }
        ::posix_spawn_file_actions_adddup2(&actions, pipe_in[0], STDIN_FILENO);
        ::posix_spawn_file_actions_adddup2(&actions, pipe_out[1], STDOUT_FILENO);
        ::posix_spawn_file_actions_addclose(&actions, pipe_in[0]);
        ::posix_spawn_file_actions_addclose(&actions, pipe_in[1]);
        ::posix_spawn_file_actions_addclose(&actions, pipe_out[0]);
        ::posix_spawn_file_actions_addclose(&actions, pipe_out[1]);

        // Belt-and-braces over per-fd O_CLOEXEC: POSIX_SPAWN_CLOEXEC_DEFAULT
        // (an Apple extension) makes every descriptor close-on-exec except the
        // two we re-target onto stdio above, so nothing else the host left open
        // — sockets, upstream-server pipes — survives into the agent.
        ::posix_spawnattr_t attr{};
        if (int rc = ::posix_spawnattr_init(&attr); rc != 0) {
            ::posix_spawn_file_actions_destroy(&actions);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"spawnattr_init: "} + std::strerror(rc));
        }
        if (int rc = ::posix_spawnattr_setpgroup(&attr, 0); rc != 0) {
            ::posix_spawnattr_destroy(&attr);
            ::posix_spawn_file_actions_destroy(&actions);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"spawnattr_setpgroup: "} + std::strerror(rc));
        }
        constexpr short spawn_flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP;
        if (int rc = ::posix_spawnattr_setflags(&attr, spawn_flags); rc != 0) {
            ::posix_spawnattr_destroy(&attr);
            ::posix_spawn_file_actions_destroy(&actions);
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"spawnattr_setflags: "} + std::strerror(rc));
        }

        std::vector<std::string> argv_owned = sandboxed_argv(effective, argv, std::move(*resolved));
        std::vector<std::string> env_owned = sandboxed_env(effective);
        std::vector<char*> argv_ptrs;
        argv_ptrs.reserve(argv_owned.size() + 1);
        for (auto& a : argv_owned) {
            argv_ptrs.push_back(a.data());
        }
        argv_ptrs.push_back(nullptr);
        std::vector<char*> envp;
        envp.reserve(env_owned.size() + 1);
        for (auto& e : env_owned) {
            envp.push_back(e.data());
        }
        envp.push_back(nullptr);

        ::pid_t pid = -1;
        const int rc = ::posix_spawnp(
            &pid, argv_owned[0].c_str(), &actions, &attr, argv_ptrs.data(), envp.data()
        );
        ::posix_spawn_file_actions_destroy(&actions);
        ::posix_spawnattr_destroy(&attr);
        if (rc != 0) {
            close_pipe_pair(pipe_in);
            close_pipe_pair(pipe_out);
            return std::unexpected(std::string{"posix_spawnp: "} + std::strerror(rc));
        }

        // Parent closes child-side ends.
        ::close(pipe_in[0]);
        ::close(pipe_out[1]);

        auto t = std::make_unique<pipe_transport>(pipe_in[1], pipe_out[0]);
        return std::make_unique<macos_agent_handle>(pid, std::move(t));
    }
};

} // namespace

auto make_default_spawner() -> std::unique_ptr<spawner> {
    return std::make_unique<macos_spawner>();
}

auto exec_contained(const profile& prof, const std::vector<std::string>& argv)
    -> std::expected<int, std::string> {
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    // The macOS backend has no private-loopback descriptor bridge, so a profile
    // that names a reverse endpoint cannot reach it. Reject rather than launch
    // an agent that silently cannot authenticate, matching the fail-closed rule
    // that a backend must not advertise enforcement it did not construct.
    if (checked->bridge_endpoint) {
        return std::unexpected(
            std::string{"bridge_endpoint is not implemented on the macOS backend"}
        );
    }
    if (auto limits = require_resource_enforcement(*checked, macos_resource_capabilities());
        !limits) {
        return std::unexpected(limits.error());
    }
    return exec_passthrough(prof, argv);
}

} // namespace glove::container
