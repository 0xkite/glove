// macOS spawner. Arbitrary agents are launched through sandbox-exec with a
// deny-default SBPL profile before their first instruction.

#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/container/system_services.hpp"
#include "glove/mcp/transport.hpp"

#include "darwin_process_group.hpp"
#include "denial_tag.hpp"
#include "launch_command.hpp"
#include "runtime_filesystem.hpp"

#include <crt_externs.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
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

// Process identity is the unreaped parent-child relation, not the PID. Until
// this handle reaps the leader, its PID cannot be reused and its PGID cannot be
// reallocated, so group signals reach only the agent's own group. Exit is
// therefore observed with WNOWAIT, the group is killed and proven empty while
// the zombie still pins it, and the leader is consumed last. After the reap,
// or once another reaper has taken the child (ECHILD), no PID or PGID
// operation is permitted.
class macos_agent_handle final : public agent_handle {
public:
    macos_agent_handle(::pid_t pid, std::unique_ptr<pipe_transport> t)
        : pid_{pid}, transport_{std::move(t)} {}

    macos_agent_handle(const macos_agent_handle&) = delete;
    macos_agent_handle& operator=(const macos_agent_handle&) = delete;
    macos_agent_handle(macos_agent_handle&&) = delete;
    macos_agent_handle& operator=(macos_agent_handle&&) = delete;

    ~macos_agent_handle() override {
        transport_.reset();
        if (!waited_) {
            // A destructor cannot report. wait() escalates SIGTERM to SIGKILL,
            // drains the group, and reaps; its remaining failures leave nothing
            // a destructor could safely retry.
            try {
                [[maybe_unused]] const auto drained = wait();
            } catch (...) {
                // wait() builds error strings, so it can throw. Leave no live
                // group or zombie: the leader is still ours while owned_.
                signal_group(SIGKILL);
                if (owned_) {
                    int status = 0;
                    while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
                    owned_ = false;
                }
            }
        }
    }

    auto transport() -> glove::mcp::transport& override { return *transport_; }

    [[nodiscard]] auto reaped_exit_code() const noexcept -> std::optional<int> override {
        return reaped_code_;
    }

    auto wait() -> std::expected<int, std::string> override {
        if (waited_) {
            if (!cached_error_.empty()) {
                return std::unexpected(cached_error_);
            }
            return cached_code_;
        }
        auto exited = observe_with_grace();
        if (!exited) {
            // An unexplained observation failure must not leave the agent
            // running: while ownership holds, kill and consume the leader.
            signal_group(SIGKILL);
            [[maybe_unused]] const auto consumed = reap();
            return finish(std::unexpected(std::move(exited.error())));
        }
        std::string drain_error = drain_group();
        auto reaped = reap();
        if (!reaped) {
            return finish(std::unexpected(std::move(reaped.error())));
        }
        if (!drain_error.empty()) {
            return finish(std::unexpected(std::move(drain_error)));
        }
        return finish(*reaped);
    }

    [[nodiscard]] auto resource_receipt() const
        -> std::expected<resource_enforcement_receipt, std::string> override {
        return std::unexpected(std::string{"resource enforcement receipt unavailable"});
    }

private:
    static constexpr int grace_polls = 50;
    static constexpr ::useconds_t poll_interval_us = 10 * 1000;
    static constexpr int drain_polls = 600; // ~3 s at 5 ms.
    static constexpr ::useconds_t drain_interval_us = 5 * 1000;

    enum class observation : std::uint8_t { running, exited };

    // Observe without consuming: the zombie keeps pinning PID and PGID.
    auto observe(bool nonblocking) -> std::expected<observation, std::string> {
        siginfo_t information{};
        int rc = -1;
        do {
            rc = ::waitid(
                P_PID,
                static_cast<id_t>(pid_),
                &information,
                WEXITED | WNOWAIT | (nonblocking ? WNOHANG : 0)
            );
        } while (rc < 0 && errno == EINTR);
        if (rc != 0) {
            const int error = errno;
            if (error == ECHILD) {
                // Ownership lost to a competing reaper: never signal again.
                owned_ = false;
            }
            return std::unexpected("waitid WNOWAIT: errno " + std::to_string(error));
        }
        if (information.si_pid == 0 && nonblocking) {
            return observation::running;
        }
        if (information.si_pid != pid_) {
            return std::unexpected(std::string{"waitid WNOWAIT returned another process"});
        }
        return observation::exited;
    }

    // Signals are sent only while observe() has not lost ownership. The
    // leader is unreaped here, so -pid_ is the agent's own group.
    void signal_group(int number) const {
        if (owned_) {
            (void)::kill(-pid_, number);
            // The leader may have left its group; KILL must still reach it.
            if (number == SIGKILL) {
                (void)::kill(pid_, SIGKILL);
            }
        }
    }

    auto poll_for_exit(int polls) -> std::expected<bool, std::string> {
        for (int spin = 0; spin < polls; ++spin) {
            auto seen = observe(true);
            if (!seen) {
                return std::unexpected(std::move(seen.error()));
            }
            if (*seen == observation::exited) {
                return true;
            }
            ::usleep(poll_interval_us);
        }
        return false;
    }

    auto observe_with_grace() -> std::expected<void, std::string> {
        auto exited = poll_for_exit(grace_polls);
        if (exited && !*exited) {
            signal_group(SIGTERM);
            exited = poll_for_exit(grace_polls);
        }
        if (!exited) {
            return std::unexpected(std::move(exited.error()));
        }
        if (!*exited) {
            signal_group(SIGKILL);
            auto seen = observe(false);
            if (!seen) {
                return std::unexpected(std::move(seen.error()));
            }
        }
        return {};
    }

    // Descendants outliving the leader are killed and proven gone before the
    // reap releases the PGID. Members that moved to another group are outside
    // this mechanism; macOS has no containing equivalent of a cgroup.
    // A listing truncated by the fixed bound counts as live members, so a
    // large group is still killed until it fits or the deadline passes.
    auto drain_group() -> std::string {
        bool truncated = false;
        for (int spin = 0; spin < drain_polls; ++spin) {
            auto still_owned = observe(true);
            if (!still_owned) {
                return "agent group drain: " + still_owned.error();
            }
            if (::kill(-pid_, SIGKILL) != 0 && errno != ESRCH && errno != EPERM) {
                return "agent group drain: kill errno " + std::to_string(errno);
            }
            const auto live = macos_detail::group_has_live_members(pid_);
            truncated = !live && live.error() == EOVERFLOW;
            if (!live && !truncated) {
                return "agent group drain: inspection errno " + std::to_string(live.error());
            }
            if (live && !*live) {
                return {};
            }
            ::usleep(drain_interval_us);
        }
        if (truncated) {
            return std::string{
                "agent group drain: listing truncated and descendants still live after SIGKILL"
            };
        }
        return std::string{"agent group drain: descendants still live after SIGKILL"};
    }

    auto reap() -> std::expected<int, std::string> {
        if (!owned_) {
            return std::unexpected(std::string{"agent leader reaped by another waiter"});
        }
        int status = 0;
        ::pid_t waited = -1;
        do {
            waited = ::waitpid(pid_, &status, 0);
        } while (waited < 0 && errno == EINTR);
        owned_ = false; // No PID or group operation is permitted beyond this point.
        if (waited != pid_) {
            return std::unexpected("waitpid: errno " + std::to_string(waited < 0 ? errno : EIO));
        }
        reaped_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return *reaped_code_;
    }

    auto finish(std::expected<int, std::string> result) -> std::expected<int, std::string> {
        waited_ = true;
        if (result) {
            cached_code_ = *result;
        } else {
            cached_error_ = result.error();
        }
        return result;
    }

    ::pid_t pid_;
    std::unique_ptr<pipe_transport> transport_;
    bool owned_ = true;
    bool waited_ = false;
    int cached_code_ = -1;
    std::string cached_error_;
    std::optional<int> reaped_code_;
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

auto regex_literal(std::string_view text, bool fold_case = false) -> std::string {
    std::string out;
    for (const char c : text) {
        if (fold_case && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) {
            const char lower = c >= 'a' && c <= 'z' ? c : static_cast<char>(c - 'A' + 'a');
            out += '[';
            out += lower;
            out += static_cast<char>(lower - 'a' + 'A');
            out += ']';
        } else {
            if (std::string_view{R"(\.^$|()[]{}*+?)"}.contains(c)) {
                out += '\\';
            }
            out += c;
        }
    }
    return out;
}

// Every deny rule ends with this modifier; the tag is hex, so it needs no
// sbpl_escape.
auto tag_modifier(std::string_view denial_tag) -> std::string {
    return std::string{" (with message \""} + std::string{denial_tag} + "\")";
}

auto append_grant_root_guard(
    std::string& policy, std::string_view root, std::string_view denial_tag
) -> void {
    // Grant children write access without allowing the grant root's namespace
    // or security metadata to move out from under immutable/reserved paths.
    policy +=
        "(deny file-write-unlink file-write-mode file-write-owner file-write-flags (literal \"";
    policy += sbpl_escape(root);
    policy += "\")";
    policy += tag_modifier(denial_tag);
    policy += ")\n";
}

// system.sb provides the platform's dynamic-loader and Mach-service plumbing.
// Opening terminal paths stays denied; CLOEXEC_DEFAULT leaves only inherited
// stdio, whose terminal inspection and raw-mode commands an interactive agent
// needs. Both the session path and exec_passthrough require it, and the grant is
// scoped to TTY vnodes the process already holds.
auto append_terminal_ioctl_rule(std::string& profile_text) -> void {
    profile_text += "(allow file-ioctl (require-all (vnode-type TTY) (require-any";
    for (const auto command : {TIOCGETA, TIOCSETA, TIOCSETAW, TIOCSETAF, TIOCGPGRP, TIOCGWINSZ}) {
        profile_text += " (ioctl-command " + std::to_string(command) + ")";
    }
    profile_text += ")))\n";
}

// Every deny rule must carry the launch's denial tag. A deny rule added
// without it produces denials the session's telemetry cannot see, and a later
// untagged rule overrides a tagged one for the operations it decides
// (measured: the kernel appends the message only of the rule that decided).
auto generate_sbpl(const profile& prof, std::string_view agent_program, std::string_view denial_tag)
    -> std::string {
    const auto tagged = tag_modifier(denial_tag);
    std::string p = "(version 1)\n(deny default" + tagged + ")\n(import \"system.sb\")\n";
    p += "(allow process-exec*)\n(allow process-fork)\n(allow sysctl-read)\n";
    // Agents and harnesses must be able to stop their own descendants; processes
    // outside the sandbox stay unsignalable under (deny default).
    p += "(allow signal (target same-sandbox))\n";
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
    for (const auto& rule : prof.runtime_filesystem) {
        append_read_rule(p, rule.path);
        append_parent_metadata_rules(p, rule.path);
    }
    // Symlinks in a grant's spelling: path resolution needs their metadata, but
    // never their content or any sibling link.
    for (const auto& link : prof.link_spellings) {
        p += "(allow file-read-metadata (literal \"";
        p += sbpl_escape(link);
        p += "\"))\n";
        append_parent_metadata_rules(p, link);
    }
    // Opt-in host system services. validate() already refused names outside the
    // catalog and derived the canonical read paths, so this only renders the
    // selected entries; an empty selection emits nothing. Allow rules carry no
    // denial tag, like the other allows.
    for (const auto& name : prof.system_services) {
        if (const auto* entry = find_system_service(name)) {
            for (const auto service : entry->macos_mach_services) {
                p += "(allow mach-lookup (global-name \"";
                p += sbpl_escape(service);
                p += "\"))\n";
            }
        }
    }
    for (const auto& path : prof.system_service_read_paths) {
        append_read_rule(p, path);
        append_parent_metadata_rules(p, path);
    }
    p += "(deny network*" + tagged + ")\n";
    // The imported system profile grants exactly one network endpoint - the
    // host syslog datagram socket - and a filtered allow outranks the
    // unfiltered deny above. Close that path class explicitly so the import
    // cannot silently widen the documented deny-default network boundary as
    // Apple regenerates system.sb. The bridge and proxy allows below carry
    // remote filters, so a path-filtered deny does not affect them.
    // /var/run is a symlink to /private/var/run and rule strings are matched
    // against the resolved path only, so a "/var/run" spelling matches nothing.
    p += "(deny network-outbound (subpath \"/private/var/run\")" + tagged + ")\n";
    if (prof.bridge_endpoint) {
        // SBPL rejects numeric hosts. Its localhost filter plus AF_INET selects
        // 127.0.0.1 only; TCP excludes an unrelated UDP service on the same port.
        p += "(allow network-outbound (require-all (remote tcp \"localhost:";
        p += std::to_string(prof.bridge_endpoint->port);
        p += "\") (socket-domain AF_INET)))\n";
    }
    for (const std::uint16_t port : prof.service_ports) {
        // Plain uncredentialed loopback services: the same rule form as the
        // bridge endpoint above, one exact IPv4 TCP port each.
        p += "(allow network-outbound (require-all (remote tcp \"localhost:";
        p += std::to_string(port);
        p += "\") (socket-domain AF_INET)))\n";
    }
    if (prof.proxy) {
        // The egress proxy always advertises a numeric 127.0.0.1 URL, so the
        // AF_INET socket-domain filter costs nothing and keeps this rule from
        // also admitting IPv6 ::1. Without it, `remote ip "localhost:PORT"`
        // matches both loopback families, which contradicts the documented
        // "no IPv6 egress" boundary and the bridged-endpoint rule below.
        p += "(allow network-outbound (require-all (remote tcp \"localhost:";
        p += std::to_string(prof.proxy->port);
        p += "\") (socket-domain AF_INET)))\n";
    }
    if (prof.unix_socket_endpoint) {
        // connect() on a Unix socket is network-outbound, not a file read, so the
        // unfiltered deny above would kill a mediated broker such as the MCP
        // bridge. validate() stored the canonical path, which is the form the
        // kernel matches; the caller's $TMPDIR spelling would never match.
        p += "(allow network-outbound (literal \"";
        p += sbpl_escape(*prof.unix_socket_endpoint);
        p += "\"))\n";
    }
    p += "(deny file-write*" + tagged + ")\n";
    for (const auto& rule : prof.filesystem) {
        if (rule.writable) {
            p += "(allow file-write* (literal \"";
            p += sbpl_escape(rule.path);
            p += "\") (subpath \"";
            p += sbpl_escape(rule.path);
            p += "\"))\n";
            // A writable grant lets its own holder unlink an empty root and
            // replace it with a symlink. The next launch canonicalizes that
            // path and would silently grant the link target, so keep the root
            // node itself inside the grant. Children stay writable.
            append_grant_root_guard(p, rule.path, denial_tag);
        }
    }
    for (const auto& file : prof.immutable_files) {
        p += "(deny file-write* (literal \"";
        p += sbpl_escape(file);
        p += "\")" + tagged + ")\n";
        append_grant_root_guard(p, std::filesystem::path{file}.parent_path().string(), denial_tag);
    }
    for (const auto& entry : prof.reserved_entries) {
        const auto pattern =
            "^" + regex_literal(entry.parent) + "/" + regex_literal(entry.name, true) + "(/|$)";
        // Ordinary string syntax handles both quote and backslash path bytes;
        // raw #"regex" syntax cannot safely encode an embedded quote.
        p += "(deny file-read* file-write* (regex \"";
        p += sbpl_escape(pattern);
        p += "\")" + tagged + ")\n";
        append_grant_root_guard(p, entry.parent, denial_tag);
    }
    return p;
}

// Wrap the agent in `sandbox-exec -p <profile>` so an arbitrary, non-glove-aware
// binary (node, python, a real coding agent) is contained by an OS-enforced
// SBPL profile applied before its first instruction — not left to self-sandbox
// the way the synthetic agent does. sandbox-exec compiles + applies the
// profile, then exec()s the target.
struct sandboxed_command {
    std::vector<std::string> argv;
    std::string denial_tag;
};

auto sandboxed_argv(
    const profile& prof, const std::vector<std::string>& argv, std::string resolved_program
) -> sandboxed_command {
    sandboxed_command out{
        .argv = {},
        .denial_tag = prof.denial_tag ? *prof.denial_tag : macos_detail::make_denial_tag(),
    };
    out.argv.reserve(argv.size() + 3);
    out.argv.emplace_back("/usr/bin/sandbox-exec");
    out.argv.emplace_back("-p");
    out.argv.emplace_back(generate_sbpl(prof, resolved_program, out.denial_tag));
    out.argv.emplace_back(std::move(resolved_program));
    for (std::size_t i = 1; i < argv.size(); ++i) {
        out.argv.push_back(argv[i]);
    }
    return out;
}

// A profile that does not compile is a construction failure, not an agent
// exit. sandbox-exec reports a bad profile only on its own stderr with exit 65,
// and only after posix_spawn has already succeeded, so the parent would record
// it as the agent's own exit code and never learn that containment was absent.
// Compile the exact text first by running it against /usr/bin/true: the probe
// also proves the profile admits the dynamic loader and /usr/bin, which every
// launch needs.
auto profile_compiles(const std::string& profile_text) -> std::expected<void, std::string> {
    std::vector<std::string> argv{"/usr/bin/sandbox-exec", "-p", profile_text, "/usr/bin/true"};
    std::vector<char*> argv_ptrs;
    argv_ptrs.reserve(argv.size() + 1);
    for (auto& argument : argv) {
        argv_ptrs.push_back(argument.data());
    }
    argv_ptrs.push_back(nullptr);
    ::pid_t pid = -1;
    char** environment = *_NSGetEnviron();
    if (const int rc =
            ::posix_spawn(&pid, argv[0].c_str(), nullptr, nullptr, argv_ptrs.data(), environment);
        rc != 0) {
        return std::unexpected(std::string{"profile probe: "} + std::strerror(rc));
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(std::string{"profile probe: "} + std::strerror(errno));
    }
    if (!WIFEXITED(status)) {
        return std::unexpected(std::string{"profile probe: terminated by signal"});
    }
    const int code = WEXITSTATUS(status);
    if (code != 0) {
        return std::unexpected(
            "generated sandbox profile does not compile (sandbox-exec exit " +
            std::to_string(code) + ")"
        );
    }
    return {};
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
        if (!prof.service_ports.empty()) {
            if (!has_environment_name(env, "NO_PROXY")) {
                env.emplace_back("NO_PROXY=127.0.0.1,localhost");
            }
            if (!has_environment_name(env, "no_proxy")) {
                env.emplace_back("no_proxy=127.0.0.1,localhost");
            }
        }
    }
    return env;
}

// Synchronously run argv contained, with the parent's stdio (0/1/2) inherited —
// no MCP pipe, no kernel. Blocks until the agent exits; returns its code. Used
// by `glove exec` for a real, self-driving agent (its terminal + LLM are its
// own; glove is the perimeter + egress, not an MCP counterparty).
auto exec_passthrough(
    const profile& prof, const std::vector<std::string>& argv, std::chrono::milliseconds stop_grace
) -> std::expected<int, std::string> {
    // Inherited stdio that is a regular file needs a metadata-only grant on its
    // path (runtimes stat their stdio); nothing else about it is readable.
    std::vector<std::string> stdio_files;
    for (const int fd : {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO}) {
        struct ::stat st{};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        std::array<char, MAXPATHLEN> path_buf{};
        if (::fcntl(fd, F_GETPATH, path_buf.data()) == 0 && path_buf[0] == '/') {
            stdio_files.emplace_back(path_buf.data());
        }
    }
    // The owned launch keeps the child unreaped until cleanup is decided, so a
    // SIGTERM, SIGINT, SIGHUP or SIGQUIT sent to glove is passed to the agent,
    // escalated to SIGKILL after a grace period, and control returns to the
    // caller, which still has its exit record and cleanup to do.
    return macos_detail::exec_owned_with_stdio_files(
        prof, argv, std::move(stdio_files), stop_grace
    );
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
        if (auto limits = require_resource_enforcement(*checked, resource_capabilities());
            !limits) {
            return std::unexpected(limits.error());
        }
        if (auto runtime = macos_detail::validate_runtime_filesystem(checked->runtime_filesystem);
            !runtime) {
            return std::unexpected(runtime.error());
        }
        if (auto constraints = macos_detail::validate_launch_constraints(*checked); !constraints) {
            return std::unexpected(constraints.error());
        }
        const auto& effective = *checked;
        auto resolved = resolve_program(effective, argv.front());
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        // Build and compile the profile before allocating pipes or spawn attributes,
        // so a profile that does not build fails the launch rather than surfacing
        // later as the agent's own exit code.
        auto command = sandboxed_argv(effective, argv, std::move(*resolved));
        std::vector<std::string> argv_owned = std::move(command.argv);
        // read by denial telemetry once it is wired in
        [[maybe_unused]] const std::string denial_tag = std::move(command.denial_tag);
        std::vector<std::string> env_owned = sandboxed_env(effective);
        if (auto compiled = profile_compiles(argv_owned[2]); !compiled) {
            return std::unexpected(compiled.error());
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

auto macos_detail::prepare_launch_command(
    const profile& prof,
    const std::vector<std::string>& argv,
    bool terminal_stdio,
    const std::vector<std::string>& stdio_files
) -> std::expected<macos_detail::launch_command, std::string> {
    if (argv.empty()) {
        return std::unexpected(std::string{"spawner: empty argv"});
    }
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (auto limits = require_resource_enforcement(*checked, macos_resource_capabilities());
        !limits) {
        return std::unexpected(limits.error());
    }
    if (auto runtime = validate_runtime_filesystem(checked->runtime_filesystem); !runtime) {
        return std::unexpected(runtime.error());
    }
    if (auto constraints = validate_launch_constraints(*checked); !constraints) {
        return std::unexpected(constraints.error());
    }
    // Added after validation, which keeps only spellings that touch a grant.
    for (const auto& path : stdio_files) {
        if (std::ranges::find(checked->link_spellings, path) == checked->link_spellings.end()) {
            checked->link_spellings.push_back(path);
        }
    }
    auto program = resolve_program(*checked, argv.front());
    if (!program) {
        return std::unexpected(program.error());
    }
    auto command = sandboxed_argv(*checked, argv, std::move(*program));
    if (auto compiled = profile_compiles(command.argv[2]); !compiled) {
        return std::unexpected(compiled.error());
    }
    if (terminal_stdio) {
        append_terminal_ioctl_rule(command.argv[2]);
    }
    return macos_detail::launch_command{
        .arguments = std::move(command.argv),
        .environment = sandboxed_env(*checked),
        .start_directory = checked->work_dir ? checked->work_dir : checked->home_dir,
        .denial_tag = std::move(command.denial_tag),
    };
}

auto make_default_spawner() -> std::unique_ptr<spawner> {
    return std::make_unique<macos_spawner>();
}

auto make_spawner(isolation_tier tier) -> std::expected<std::unique_ptr<spawner>, std::string> {
    switch (tier) {
    case isolation_tier::os_primitives:
        return make_default_spawner();
    case isolation_tier::microvm:
        return std::unexpected(std::string{"microvm isolation backend is not constructed yet"});
    }
    return std::unexpected(std::string{"unknown isolation tier"});
}

auto exec_contained(const profile& prof, const std::vector<std::string>& argv)
    -> std::expected<int, std::string> {
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (auto limits = require_resource_enforcement(*checked, macos_resource_capabilities());
        !limits) {
        return std::unexpected(limits.error());
    }
    return exec_passthrough(prof, argv, default_stop_grace);
}

auto exec_contained(
    const profile& prof, const std::vector<std::string>& argv, escape_event_observer /*on_escape*/
) -> std::expected<int, std::string> {
    return exec_contained(prof, argv);
}

auto exec_contained(
    const profile& prof,
    const std::vector<std::string>& argv,
    escape_event_observer /*on_escape*/,
    std::chrono::milliseconds stop_grace
) -> std::expected<int, std::string> {
    if (stop_grace < min_stop_grace || stop_grace > max_stop_grace) {
        return std::unexpected(std::string{"stop grace must be between 0.1 and 60 seconds"});
    }
    auto checked = validate(prof);
    if (!checked) {
        return std::unexpected(std::string{"profile: "} + checked.error());
    }
    if (auto limits = require_resource_enforcement(*checked, macos_resource_capabilities());
        !limits) {
        return std::unexpected(limits.error());
    }
    return exec_passthrough(prof, argv, stop_grace);
}

} // namespace glove::container
