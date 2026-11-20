#include "glove/run/runner.hpp"

#include "glove/audit/event.hpp"
#include "glove/audit/sink.hpp"
#include "glove/container/profile.hpp"
#include "glove/container/spawner.hpp"
#include "glove/kernel/mcp_extension.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/kernel/server.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/lazy_init.hpp"
#include "glove/mcp/stdio_transport.hpp"
#include "glove/net/credentialed_endpoint.hpp"
#include "glove/net/egress_proxy.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"
#include "glove/reflect/codegen.hpp"
#include "glove/reflect/extension.hpp"
#include "glove/run/pi_host_config.hpp"

#include "provider_endpoint.hpp"

#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(__APPLE__)
#    include <mach-o/dyld.h>
#endif

extern "C" char** environ;

namespace glove::run {

namespace {

class private_runtime final {
public:
    private_runtime(const private_runtime&) = delete;
    private_runtime& operator=(const private_runtime&) = delete;

    private_runtime(private_runtime&& other) noexcept : root_{std::move(other.root_)} {
        other.root_.clear();
    }

    private_runtime& operator=(private_runtime&&) = delete;

    ~private_runtime() {
        if (!root_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(root_, ignored);
        }
    }

    static auto create() -> std::expected<private_runtime, std::string> {
        std::error_code ec;
        auto root = std::filesystem::temp_directory_path(ec);
        if (ec) {
            return std::unexpected(
                std::string{"cannot locate temporary directory: "} + ec.message()
            );
        }
        std::string pattern = (root / "glove-XXXXXX").string();
        if (::mkdtemp(pattern.data()) == nullptr) {
            return std::unexpected(std::string{"mkdtemp: "} + std::strerror(errno));
        }
        return private_runtime{std::filesystem::path{std::move(pattern)}};
    }

    auto root() const -> const std::filesystem::path& { return root_; }

private:
    explicit private_runtime(std::filesystem::path root) : root_{std::move(root)} {}

    std::filesystem::path root_;
};

auto resolve_absolute(std::filesystem::path path) -> std::expected<std::string, std::string> {
    std::error_code ec;
    auto result = std::filesystem::absolute(std::move(path), ec);
    if (ec) {
        return std::unexpected(std::string{"cannot resolve path: "} + ec.message());
    }
    return result.lexically_normal().string();
}

auto append_selected_environment(
    glove::container::profile& profile,
    const std::vector<std::string>& names,
    const std::vector<std::string>& extra_path_dirs
) -> std::expected<void, std::string> {
    std::string path_entry = "PATH=";
    for (const auto& dir : extra_path_dirs) {
        if (!dir.empty()) {
            path_entry += dir + ":";
        }
    }
    path_entry += "/usr/bin:/bin:/usr/sbin:/sbin";
    profile.environment = {std::move(path_entry), "TERM=xterm-256color"};
    for (const auto& name : names) {
        if (name.empty() || name.find('=') != std::string::npos) {
            return std::unexpected(std::string{"--env requires a variable name, not NAME=VALUE"});
        }
        // Glove-managed variables, plus the outer-harness control variables.
        // The documented invariant is that the sandboxed child never receives
        // Herdr's socket path or binary path; allowing them through `--env`
        // would hand an agent the supervisor's control channel.
        for (const auto* reserved : {
                 "HOME",
                 "TMPDIR",
                 "GLOVE_SANDBOXED",
                 "HTTPS_PROXY",
                 "HTTP_PROXY",
                 "ALL_PROXY",
                 "HERDR_ENV",
                 "HERDR_PANE_ID",
                 "HERDR_BIN_PATH",
                 "HERDR_SOCKET_PATH",
                 "HERDR_AGENT",
             }) {
            if (name == reserved) {
                return std::unexpected(
                    std::string{"--env cannot override glove-managed variable "} + name
                );
            }
        }
        const char* value = std::getenv(name.c_str());
        if (value == nullptr) {
            return std::unexpected(std::string{"selected environment variable is unset: "} + name);
        }
        profile.environment.push_back(name + "=" + value);
    }
    return {};
}

auto build_profile(const options& opts, const std::filesystem::path& runtime_root)
    -> std::expected<glove::container::profile, std::string> {
    glove::container::profile profile;
    profile.allow_loopback_listen = opts.allow_loopback_listen;
    if (auto environment =
            append_selected_environment(profile, opts.environment_names, opts.extra_path_dirs);
        !environment) {
        return std::unexpected(environment.error());
    }

    profile.filesystem.push_back({.path = runtime_root.string(), .writable = true});
    profile.home_dir = (runtime_root / "home").string();
    profile.temp_dir = (runtime_root / "tmp").string();
    profile.work_dir = runtime_root.string();

    if (opts.workspace) {
        auto workspace = resolve_absolute(*opts.workspace);
        if (!workspace) {
            return std::unexpected(workspace.error());
        }
        profile.filesystem.push_back({.path = *workspace, .writable = true});
        profile.work_dir = *workspace;
    }

    for (const auto& path : opts.readable) {
        auto resolved = resolve_absolute(path);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        profile.filesystem.push_back({.path = std::move(*resolved), .writable = false});
    }
    for (const auto& path : opts.writable) {
        auto resolved = resolve_absolute(path);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        profile.filesystem.push_back({.path = std::move(*resolved), .writable = true});
    }
    return profile;
}

auto provision(const glove::container::profile& profile) -> std::expected<void, std::string> {
    for (const auto& path : {profile.home_dir, profile.temp_dir}) {
        if (!path) {
            continue;
        }
        std::error_code ec;
        std::filesystem::create_directories(*path, ec);
        if (ec) {
            return std::unexpected(
                std::string{"cannot create private sandbox directory '"} + *path +
                "': " + ec.message()
            );
        }
        std::filesystem::permissions(
            *path, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec
        );
        if (ec) {
            return std::unexpected(
                std::string{"cannot protect private sandbox directory '"} + *path +
                "': " + ec.message()
            );
        }
    }
    for (const auto& rule : profile.filesystem) {
        std::error_code ec;
        if (!std::filesystem::exists(rule.path, ec) || ec) {
            return std::unexpected(
                std::string{"explicit filesystem path does not exist: '"} + rule.path + "'"
            );
        }
    }
    return {};
}

auto path_within(const std::filesystem::path& candidate, const std::filesystem::path& root)
    -> bool {
    const auto nc = candidate.lexically_normal();
    const auto nr = root.lexically_normal();
    const auto [mr, mc] = std::ranges::mismatch(nr, nc);
    return mr == nr.end();
}

void copy_regular_file_0600(
    const std::filesystem::path& src,
    const std::filesystem::path& dst,
    bool allow_owner_symlink = false
) noexcept {
    struct ::stat link_st{};
    if (::lstat(src.c_str(), &link_st) != 0 || link_st.st_uid != ::geteuid()) {
        return;
    }
    std::filesystem::path open_path = src;
    struct ::stat expected_st = link_st;
    if (S_ISLNK(link_st.st_mode)) {
        if (!allow_owner_symlink) {
            return;
        }
        std::error_code ec;
        const auto target = std::filesystem::canonical(src, ec);
        if (ec || target.empty()) {
            return;
        }
        // Validate target constraints:
        // 1. Target filename must match src filename (prevent settings.json -> id_rsa/auth.json)
        if (target.filename() != src.filename()) {
            return;
        }
        // 2. Target must be a regular file owned by the user
        struct ::stat target_st{};
        if (::stat(target.c_str(), &target_st) != 0 || target_st.st_uid != ::geteuid() ||
            !S_ISREG(target_st.st_mode)) {
            return;
        }
        // 3. Target must not contain sensitive path components
        const std::string target_str = target.string();
        for (std::string_view sensitive :
             {".ssh",
              ".gnupg",
              ".aws",
              ".azure",
              ".kube",
              "auth.json",
              "id_rsa",
              "id_ed25519",
              "token"}) {
            if (target_str.find(sensitive) != std::string::npos) {
                return;
            }
        }
        // 4. Target must be within approved trees
        const char* home = std::getenv("HOME");
        if (home != nullptr && *home != '\0') {
            const std::filesystem::path home_path{home};
            std::error_code home_ec;
            const auto canon_home = std::filesystem::canonical(home_path, home_ec);
            if (home_ec || canon_home.empty()) {
                return;
            }
            const bool in_approved =
                path_within(target, canon_home / ".pi") ||
                path_within(target, canon_home / "Documents" / "depend" / "dotfiles") ||
                path_within(target, canon_home / ".dotfiles") ||
                path_within(target, src.parent_path());
            if (!in_approved) {
                return;
            }
        }
        open_path = target;
        expected_st = target_st;
    }
    const int in_fd = ::open(open_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in_fd < 0) {
        return;
    }
    struct ::stat before{};
    constexpr std::uint64_t kMaxGuestConfigBytes = 4U * 1024U * 1024U;
    if (::fstat(in_fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_uid != ::geteuid() ||
        before.st_dev != expected_st.st_dev || before.st_ino != expected_st.st_ino ||
        before.st_size < 0 || static_cast<std::uint64_t>(before.st_size) > kMaxGuestConfigBytes) {
        (void)::close(in_fd);
        return;
    }
    std::string contents(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const ::ssize_t n = ::read(in_fd, contents.data() + offset, contents.size() - offset);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            (void)::close(in_fd);
            return;
        }
        offset += static_cast<std::size_t>(n);
    }
    struct ::stat after{};
    if (::fstat(in_fd, &after) != 0 || after.st_dev != before.st_dev ||
        after.st_ino != before.st_ino || after.st_size != before.st_size ||
        after.st_mtime != before.st_mtime) {
        (void)::close(in_fd);
        return;
    }
    (void)::close(in_fd);

    const int out_fd =
        ::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out_fd < 0) {
        return;
    }
    std::size_t written = 0;
    while (written < contents.size()) {
        const ::ssize_t n = ::write(out_fd, contents.data() + written, contents.size() - written);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            (void)::close(out_fd);
            (void)::unlink(dst.c_str());
            return;
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fchmod(out_fd, 0600);
    (void)::close(out_fd);
}

auto detect_loopback_port_in_models_json(const std::filesystem::path& models_json_path)
    -> std::optional<std::uint16_t> {
    std::ifstream in(models_json_path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::string content((std::istreambuf_iterator<char>(in)), {});
    for (std::string_view prefix :
         {std::string_view{"http://127.0.0.1:"}, std::string_view{"http://localhost:"}}) {
        const auto pos = content.find(prefix);
        if (pos == std::string::npos) {
            continue;
        }
        std::size_t idx = pos + prefix.size();
        unsigned port = 0;
        std::size_t digits = 0;
        while (idx < content.size() && content[idx] >= '0' && content[idx] <= '9' && digits < 6) {
            port = port * 10U + static_cast<unsigned>(content[idx] - '0');
            ++idx;
            ++digits;
        }
        if (digits > 0 && port >= 1U && port <= 65535U) {
            return static_cast<std::uint16_t>(port);
        }
    }
    return std::nullopt;
}

auto read_small_file(const std::filesystem::path& path) -> std::optional<std::string> {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::nullopt;
    }
    constexpr std::size_t limit = 4U * 1024U * 1024U;
    std::string text;
    std::array<char, 8192> chunk{};
    while (text.size() <= limit) {
        const ::ssize_t n = ::read(fd, chunk.data(), chunk.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        text.append(chunk.data(), static_cast<std::size_t>(n));
    }
    (void)::close(fd);
    if (text.size() > limit) {
        return std::nullopt;
    }
    return text;
}

// Replace a staged guest file through a same-directory temporary so a failed
// write leaves the previous copy, never a truncated one.
auto replace_file_0600(const std::filesystem::path& path, std::string_view text) -> bool {
    const auto tmp = path.string() + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    std::size_t written = 0;
    bool ok = true;
    while (written < text.size()) {
        const ::ssize_t n = ::write(fd, text.data() + written, text.size() - written);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            ok = false;
            break;
        }
        written += static_cast<std::size_t>(n);
    }
    (void)::fchmod(fd, 0600);
    (void)::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
        (void)::unlink(tmp.c_str());
        return false;
    }
    return true;
}

// Point local Pi packages at absolute paths the sandbox can read, and drop the
// ones it cannot so Pi starts instead of aborting on an unreadable manifest.
// Relative sources resolve from the host agent directory, as Pi resolves them.
void stage_guest_pi_settings(
    const std::filesystem::path& host_home,
    const std::filesystem::path& host_pi_dir,
    const std::filesystem::path& guest_pi_dir,
    const glove::container::profile& profile,
    bool report
) {
    const auto guest_settings = guest_pi_dir / "settings.json";
    if (!std::filesystem::exists(std::filesystem::symlink_status(guest_settings))) {
        return;
    }
    const auto text = read_small_file(guest_settings);
    if (!text) {
        (void)::unlink(guest_settings.c_str());
        return;
    }
    auto packages = glove::run::pi_local_package_sources(*text, host_pi_dir, host_home);
    if (!packages) {
        // Keep the copy as staged: losing defaultProvider/defaultModel is worse
        // than a local package path that may not resolve in the sandbox.
        std::fprintf(
            stderr,
            "glove: Pi settings.json staged unchanged; local package paths not rewritten: %s\n",
            packages.error().c_str()
        );
        return;
    }
    std::map<std::string, std::string> exposed;
    for (const auto& package : *packages) {
        // Entries under the agent directory keep their original form: the
        // guest mirrors npm, skills, pi-subagents, pi-web-access, and missions
        // there, and anything else under it was not loadable before either.
        if (path_within(package.resolved, host_pi_dir)) {
            const std::string_view declared{package.declared};
            exposed.emplace(
                package.declared,
                std::string{declared.starts_with('+') ? declared.substr(1) : declared}
            );
            continue;
        }
        auto canonical = glove::run::pi_package_exposure(package.resolved, host_home, host_pi_dir);
        const auto covers = [&](const auto& rule) {
            return path_within(*canonical, std::filesystem::path{rule.path});
        };
        if (canonical && std::ranges::any_of(profile.filesystem, covers)) {
            exposed.emplace(package.declared, canonical->string());
            continue;
        }
        if (!report) {
            continue;
        }
        std::string reason = canonical ? "path is not exposed" : canonical.error();
        if (canonical && std::ranges::any_of(profile.filesystem, [&](const auto& rule) {
                return path_within(std::filesystem::path{rule.path}, *canonical);
            })) {
            reason = "it contains the workspace or another mounted path; use a workspace "
                     "outside it";
        }
        std::fprintf(
            stderr,
            "glove: Pi resource '%s' is not loaded in the sandbox (%s)\n",
            glove::run::printable(package.declared).c_str(),
            glove::run::printable(reason).c_str()
        );
    }
    auto rewritten = glove::run::rewrite_pi_settings_packages(*text, exposed);
    if (!rewritten || !replace_file_0600(guest_settings, *rewritten)) {
        std::fprintf(stderr, "glove: Pi settings.json not staged: cannot rewrite packages\n");
        (void)::unlink(guest_settings.c_str());
    }
}

// Remove credentials from the staged models.json; on any failure the guest
// gets no models.json rather than an unscrubbed one.
void stage_guest_pi_models(const std::filesystem::path& guest_pi_dir) {
    const auto guest_models = guest_pi_dir / "models.json";
    if (!std::filesystem::exists(std::filesystem::symlink_status(guest_models))) {
        return;
    }
    const auto text = read_small_file(guest_models);
    auto scrubbed = text ? glove::run::scrub_pi_models_credentials(*text)
                         : std::expected<std::string, std::string>{std::unexpected("unreadable")};
    if (!scrubbed || !replace_file_0600(guest_models, *scrubbed)) {
        std::fprintf(stderr, "glove: Pi models.json not staged: cannot remove credentials\n");
        (void)::unlink(guest_models.c_str());
    }
}

void provision_guest_agent_home(const options& opts, glove::container::profile& profile) noexcept {
    if (!opts.seed_guest_agent_home || !profile.home_dir) {
        return;
    }
    if (opts.egress.empty()) {
        profile.environment.push_back("PI_OFFLINE=1");
        profile.environment.push_back("NPM_CONFIG_OFFLINE=true");
    }
    profile.environment.push_back("NPM_CONFIG_UPDATE_NOTIFIER=false");

    const char* host_home_env = std::getenv("HOME");
    if (host_home_env == nullptr || *host_home_env == '\0') {
        return;
    }
    std::error_code ec;
    const std::filesystem::path host_home{host_home_env};
    const std::filesystem::path guest_home{*profile.home_dir};

    const auto host_pi_dir = host_home / ".pi" / "agent";
    if (std::filesystem::is_directory(host_pi_dir, ec) && !ec) {
        const auto guest_pi_dir = guest_home / ".pi" / "agent";
        std::filesystem::create_directories(guest_pi_dir / "sessions", ec);
        std::filesystem::permissions(
            guest_pi_dir,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec
        );
        // Copy non-credential configuration files (allowing owner-owned dotfile
        // symlinks for settings.json/models.json/pi-recurse.json). Raw host
        // credential files (`auth.json`) are never copied; write an empty `{}`
        // `auth.json` matching the native Pi adapter contract.
        for (const char* name : {
                 "settings.json",
                 "models.json",
                 "models-store.json",
                 "mcp-onboarding.json",
                 "mcp-last-seen-version.json",
                 "trust.json",
                 "pi-recurse.json",
             }) {
            copy_regular_file_0600(host_pi_dir / name, guest_pi_dir / name, true);
        }
        stage_guest_pi_settings(
            host_home, host_pi_dir, guest_pi_dir, profile, opts.report_pi_packages
        );
        stage_guest_pi_models(guest_pi_dir);
        // Strictly preserve credential boundary: guest auth.json is ALWAYS empty `{}`.
        const auto guest_auth = guest_pi_dir / "auth.json";
        const int auth_fd =
            ::open(guest_auth.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (auth_fd >= 0) {
            (void)::write(auth_fd, "{}\n", 3);
            (void)::fchmod(auth_fd, 0600);
            (void)::close(auth_fd);
        }
        // Symlink read-only installed package/skill directories into the guest
        // PI_CODING_AGENT_DIR so Pi finds `lsp-pi` and installed extensions
        // locally without invoking `npm install` against registry.npmjs.org.
        for (const char* dir_name :
             {"npm", "skills", "pi-subagents", "pi-web-access", "missions"}) {
            const auto src_dir = host_pi_dir / dir_name;
            const auto dst_link = guest_pi_dir / dir_name;
            struct ::stat st{};
            if (::lstat(src_dir.c_str(), &st) != 0 || st.st_uid != ::geteuid()) {
                continue;
            }
            std::error_code canon_ec;
            const auto canon = std::filesystem::canonical(src_dir, canon_ec);
            if (canon_ec || canon.empty()) {
                continue;
            }
            struct ::stat cst{};
            if (::stat(canon.c_str(), &cst) != 0 || !S_ISDIR(cst.st_mode) ||
                cst.st_uid != ::geteuid()) {
                continue;
            }
            const std::string canon_str = canon.string();
            if (canon_str.find(".ssh") != std::string::npos ||
                canon_str.find("auth.json") != std::string::npos) {
                continue;
            }
            const bool in_approved =
                path_within(canon, host_pi_dir) ||
                path_within(canon, host_home / "Documents" / "depend" / "dotfiles") ||
                path_within(canon, host_home / ".dotfiles");
            if (!in_approved) {
                continue;
            }
            if (!std::filesystem::exists(dst_link, ec)) {
                std::filesystem::create_directory_symlink(canon, dst_link, ec);
            }
        }
        profile.environment.push_back("PI_CODING_AGENT_DIR=" + guest_pi_dir.string());
    }

    // Symlink read-only Sage config, skill libraries, and rustup toolchains
    // into the guest HOME so agent plugins and Rust tools (`cargo`/`rustc`) work offline.
    for (const auto& rel : {
             std::filesystem::path{".config"} / "sage",
             std::filesystem::path{".local"} / "share" / "sage",
             std::filesystem::path{".rustup"},
         }) {
        const auto src_dir = host_home / rel;
        const auto dst_link = guest_home / rel;
        struct ::stat st{};
        if (::lstat(src_dir.c_str(), &st) != 0 || st.st_uid != ::geteuid()) {
            continue;
        }
        std::error_code canon_ec;
        const auto canon = std::filesystem::canonical(src_dir, canon_ec);
        if (canon_ec || canon.empty()) {
            continue;
        }
        struct ::stat cst{};
        if (::stat(canon.c_str(), &cst) != 0 || !S_ISDIR(cst.st_mode) ||
            cst.st_uid != ::geteuid()) {
            continue;
        }
        const std::string canon_str = canon.string();
        if (canon_str.find(".ssh") != std::string::npos ||
            canon_str.find(".gnupg") != std::string::npos) {
            continue;
        }
        const bool in_approved =
            path_within(canon, host_home / rel) ||
            path_within(canon, host_home / "Documents" / "depend" / "dotfiles") ||
            path_within(canon, host_home / ".dotfiles");
        if (!in_approved) {
            continue;
        }
        if (!std::filesystem::exists(dst_link, ec)) {
            std::filesystem::create_directories(dst_link.parent_path(), ec);
            std::filesystem::create_directory_symlink(canon, dst_link, ec);
        }
    }
    if (const auto rustup_dir = host_home / ".rustup";
        std::filesystem::is_directory(rustup_dir, ec) && !ec) {
        profile.environment.push_back("RUSTUP_HOME=" + rustup_dir.string());
    }

    const auto host_agy_dir = host_home / ".gemini" / "antigravity-cli";
    if (std::filesystem::is_directory(host_agy_dir, ec) && !ec) {
        const auto guest_agy_dir = guest_home / ".gemini" / "antigravity-cli";
        std::filesystem::create_directories(guest_agy_dir, ec);
        for (const char* name : {"settings.json", "installation_id"}) {
            copy_regular_file_0600(host_agy_dir / name, guest_agy_dir / name, false);
        }
    }
}

auto prepare_profile(const options& opts, const std::filesystem::path& runtime_root)
    -> std::expected<glove::container::profile, std::string> {
    auto raw = build_profile(opts, runtime_root);
    if (!raw) {
        return std::unexpected(raw.error());
    }
    auto validated = glove::container::validate(*raw);
    if (!validated) {
        return std::unexpected(std::string{"profile: "} + validated.error());
    }
    if (auto prepared = provision(*validated); !prepared) {
        return std::unexpected(prepared.error());
    }
    provision_guest_agent_home(opts, *validated);
    auto revalidated = glove::container::validate(*validated);
    if (!revalidated) {
        return std::unexpected(
            std::string{"profile changed during provisioning: "} + revalidated.error()
        );
    }
    return revalidated;
}

auto validate_audit_parent_chain(const std::filesystem::path& dir)
    -> std::expected<int, std::string> {
    if (!dir.is_absolute()) {
        return std::unexpected("audit parent directory must be absolute: " + dir.string());
    }
    const auto norm = dir.lexically_normal();
    int current_fd = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current_fd < 0) {
        return std::unexpected(std::string{"cannot open root directory: "} + std::strerror(errno));
    }
    for (const auto& part : norm) {
        const std::string name = part.string();
        if (name.empty() || name == "/") {
            continue;
        }
        int next_fd =
            ::openat(current_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0 && errno == ENOENT) {
            if (::mkdirat(current_fd, name.c_str(), 0700) != 0 && errno != EEXIST) {
                const int err = errno;
                (void)::close(current_fd);
                return std::unexpected(
                    "cannot create audit directory component '" + name + "': " + std::strerror(err)
                );
            }
            next_fd =
                ::openat(current_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next_fd < 0) {
            const int err = errno;
            (void)::close(current_fd);
            return std::unexpected(
                "cannot open audit directory component '" + name + "': " + std::strerror(err)
            );
        }
        (void)::close(current_fd);
        current_fd = next_fd;

        struct ::stat st{};
        if (::fstat(current_fd, &st) != 0) {
            const int err = errno;
            (void)::close(current_fd);
            return std::unexpected(
                "cannot stat audit directory component '" + name + "': " + std::strerror(err)
            );
        }
        if (!S_ISDIR(st.st_mode)) {
            (void)::close(current_fd);
            return std::unexpected("audit directory component is not a directory: '" + name + "'");
        }
        // Reject group/world-writable directories unless sticky bit is set (e.g. /tmp).
        if ((st.st_mode & 0022) != 0 && !(st.st_mode & S_ISVTX)) {
            (void)::close(current_fd);
            return std::unexpected(
                "audit directory component has unsafe permissions (group/world writable): '" +
                name + "'"
            );
        }
        // Verify ownership: root or current user.
        if (st.st_uid != ::geteuid() && st.st_uid != 0) {
            (void)::close(current_fd);
            return std::unexpected(
                "audit directory component not owned by current user or root: '" + name + "'"
            );
        }
        // Tighten permissions on user-owned components:
        if (st.st_uid == ::geteuid()) {
            if (::fchmod(current_fd, 0700) != 0) {
                const int err = errno;
                (void)::close(current_fd);
                return std::unexpected(
                    "cannot tighten permissions on audit directory component '" + name +
                    "': " + std::strerror(err)
                );
            }
        }
    }
    return current_fd;
}

auto audit_destination(
    const std::optional<std::filesystem::path>& requested, const glove::container::profile& profile
) -> std::expected<std::optional<std::filesystem::path>, std::string> {
    if (requested) {
        auto absolute = resolve_absolute(*requested);
        if (!absolute) {
            return std::unexpected(absolute.error());
        }
        std::error_code ec;
        auto destination = std::filesystem::weakly_canonical(*absolute, ec);
        if (ec) {
            return std::unexpected(
                std::string{"cannot resolve audit destination: "} + ec.message()
            );
        }
        for (const auto& rule : profile.filesystem) {
            if (path_within(destination, std::filesystem::path{rule.path})) {
                return std::unexpected(
                    std::string{"audit destination must be outside every agent-visible path: '"} +
                    destination.string() + "'"
                );
            }
        }
        return std::optional<std::filesystem::path>{std::move(destination)};
    }

    // Default to a host state log file (`<XDG_STATE_HOME>/glove/logs/session.jsonl`)
    // when outside every agent-visible path so launch/egress/MCP audit events are
    // persisted without writing to the interactive terminal.
    std::optional<std::filesystem::path> state_base;
    if (const char* xdg_state = std::getenv("XDG_STATE_HOME");
        xdg_state != nullptr && *xdg_state == '/') {
        state_base = std::filesystem::path{xdg_state} / "glove" / "logs";
    } else if (const char* home = std::getenv("HOME"); home != nullptr && *home == '/') {
        state_base = std::filesystem::path{home} / ".local" / "state" / "glove" / "logs";
    }
    if (state_base) {
        auto valid_chain = validate_audit_parent_chain(*state_base);
        if (!valid_chain) {
            return std::unexpected("insecure default audit directory: " + valid_chain.error());
        }
        (void)::close(*valid_chain);
        std::error_code ec;
        std::filesystem::permissions(
            *state_base,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace,
            ec
        );
        if (ec) {
            return std::unexpected(
                "cannot set 0700 permissions on audit directory: " + ec.message()
            );
        }
        const auto default_log = *state_base / "session.jsonl";
        for (const auto& rule : profile.filesystem) {
            if (path_within(default_log, std::filesystem::path{rule.path}) ||
                path_within(*state_base, std::filesystem::path{rule.path})) {
                return std::unexpected(
                    std::string{"default audit log is exposed to agent filesystem mount: '"} +
                    rule.path + "'"
                );
            }
        }
        return std::optional<std::filesystem::path>{default_log};
    }
    return std::optional<std::filesystem::path>{};
}

#if defined(GLOVE_HAS_REFLECTION)
struct[[= glove::reflect::tool_meta{
    "sandbox_info", "Inspect active Glove sandbox boundaries and mediated upstreams"
}]] sandbox_info_args {
    [[= glove::reflect::param_meta{
        "detail", "Include upstream count in response", false
    }]] std::optional<bool>
        detail;
};
#endif

auto build_registry(const std::vector<upstream_spec>& upstreams)
    -> std::expected<std::unique_ptr<glove::kernel::registry>, std::string> {
    auto registry = std::make_unique<glove::kernel::registry>();
    auto reflected = std::make_unique<glove::reflect::reflected_extension>("glove");
    const std::size_t upstream_count = upstreams.size();
#if defined(GLOVE_HAS_REFLECTION)
    if (auto added = reflected->add_tool<sandbox_info_args>(
            [upstream_count](const sandbox_info_args&)
                -> std::expected<glove::mcp::tool_call_result, std::string> {
                return glove::mcp::tool_call_result{
                    .status = glove::mcp::tool_call_status::ok,
                    .content = "glove_sandboxed=true upstreams=" + std::to_string(upstream_count),
                    .structured_json = {},
                    .error_message = {},
                };
            }
        );
        !added) {
        return std::unexpected(added.error());
    }
#else
    if (auto added = reflected->add_descriptor_tool(
            glove::mcp::tool_descriptor{
                .name = "sandbox_info",
                .description = "Inspect active Glove sandbox boundaries and mediated upstreams",
                .input_schema_json = R"({"type":"object","properties":{},"required":[]})",
                .annotations = {},
            },
            [upstream_count](std::string_view)
                -> std::expected<glove::mcp::tool_call_result, std::string> {
                return glove::mcp::tool_call_result{
                    .status = glove::mcp::tool_call_status::ok,
                    .content = "glove_sandboxed=true upstreams=" + std::to_string(upstream_count),
                    .structured_json = {},
                    .error_message = {},
                };
            }
        );
        !added) {
        return std::unexpected(added.error());
    }
#endif
    if (auto added = registry->add(std::move(reflected)); !added) {
        return std::unexpected(added.error());
    }
    for (const auto& upstream : upstreams) {
        if (upstream.argv.empty()) {
            return std::unexpected(std::string{"upstream '"} + upstream.name + "': empty argv");
        }
        glove::mcp::stdio_child_options child{
            .program = upstream.argv.front(),
            .args = upstream.argv,
            .environment = {},
#if defined(__linux__)
            .sandbox = {.enabled = true, .allow_network = false},
#endif
        };
        auto transport = glove::mcp::make_stdio_transport(child);
        if (!transport) {
            return std::unexpected(
                std::string{"upstream '"} + upstream.name + "': " + transport.error()
            );
        }
        auto client = glove::mcp::make_client(std::move(*transport));
        auto lazy = glove::mcp::make_lazy_init_client(std::move(client), "glove", "0.0.1");
        auto extension = glove::kernel::make_mcp_extension(upstream.name, std::move(lazy));
        if (auto added = registry->add(std::move(extension)); !added) {
            return std::unexpected(added.error());
        }
    }
    return registry;
}

auto build_audit_sink(const std::optional<std::filesystem::path>& path, bool is_default_log)
    -> std::expected<std::shared_ptr<glove::audit::sink>, std::string> {
    if (path) {
        glove::audit::jsonl_sink_limits limits{};
        if (is_default_log) {
            limits.max_file_bytes = 10U * 1024U * 1024U;
        }
        auto file_sink = glove::audit::make_jsonl_sink(*path, limits);
        if (!file_sink) {
            return std::unexpected(
                "failed to open audit journal '" + path->string() + "': " + file_sink.error()
            );
        }
        return *file_sink;
    }
    return glove::audit::make_memory_sink();
}

auto record(
    const std::shared_ptr<glove::audit::sink>& sink,
    glove::audit::action action,
    std::string subject,
    glove::mcp::tool_call_status status = glove::mcp::tool_call_status::ok,
    std::string error = {}
) -> std::expected<void, std::string> {
    if (!sink) {
        return {};
    }
    glove::audit::event event{
        .what = action,
        .tool_name = std::move(subject),
        .arguments_json = {},
        .status = status,
        .error_message = std::move(error),
    };
    return sink->record(event);
}

auto start_egress(
    const options& opts,
    glove::container::profile& profile,
    const std::shared_ptr<glove::audit::sink>& sink
) -> std::expected<std::unique_ptr<glove::net::egress_proxy>, std::string> {
    if (opts.egress.empty()) {
        return std::unique_ptr<glove::net::egress_proxy>{};
    }
    glove::net::egress_options proxy_options;
    proxy_options.allow = opts.egress;
    proxy_options.on_event =
        [sink](const glove::net::egress_event& event) -> std::expected<void, std::string> {
        const std::string target = event.host + ":" + std::to_string(event.port);
        const auto status = event.allowed ? glove::mcp::tool_call_status::ok
                                          : glove::mcp::tool_call_status::invalid_arguments;
        if (auto audited = record(sink, glove::audit::action::egress, target, status, event.detail);
            !audited) {
            return std::unexpected(audited.error());
        }
        return {};
    };
    auto proxy = glove::net::start_egress_proxy(std::move(proxy_options));
    if (!proxy) {
        return std::unexpected(std::string{"egress proxy: "} + proxy.error());
    }
    profile.proxy = glove::container::proxy_settings{
        .port = (*proxy)->port(),
        .url = (*proxy)->proxy_url(),
    };
    return std::move(*proxy);
}

// One built-in agent preset: the provider endpoint it talks to and the
// environment variable names that steer the client at the mediated proxy.
struct preset_definition {
    glove::net::endpoint_provider provider;
    std::string_view label;
    detail::provider_surface surface;
    std::string_view base_url_env;
    std::string_view api_key_env;
};

auto preset_definition_for(std::string_view name) -> std::optional<preset_definition> {
    if (name == "claude-code" || name == "claude") {
        return preset_definition{
            .provider = glove::net::endpoint_provider::anthropic,
            .label = "claude-code",
            .surface = detail::provider_surface::legacy_anthropic,
            .base_url_env = "ANTHROPIC_BASE_URL",
            .api_key_env = "ANTHROPIC_API_KEY",
        };
    }
    if (name == "codex" || name == "openai") {
        return preset_definition{
            .provider = glove::net::endpoint_provider::openai,
            .label = "codex",
            .surface = detail::provider_surface::legacy_openai,
            .base_url_env = "OPENAI_BASE_URL",
            .api_key_env = "OPENAI_API_KEY",
        };
    }
    if (name == "pi") {
        return preset_definition{
            .provider = glove::net::endpoint_provider::anthropic,
            .label = "pi",
            .surface = detail::provider_surface::legacy_anthropic,
            .base_url_env = "ANTHROPIC_BASE_URL",
            .api_key_env = "ANTHROPIC_API_KEY",
        };
    }
    return std::nullopt;
}

// An ephemeral, non-actionable session token. The agent presents it as its API
// key; only this session's host proxy accepts it, so a leaked environment or
// transcript exposes nothing usable off-host.
auto random_session_nonce() -> std::expected<std::string, std::string> {
    std::array<unsigned char, 24> bytes{};
    if (::getentropy(bytes.data(), bytes.size()) != 0) {
        return std::unexpected(std::string{"getentropy: "} + std::strerror(errno));
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string nonce = "glove-session-";
    for (const auto byte : bytes) {
        nonce.push_back(hex[byte >> 4U]);
        nonce.push_back(hex[byte & 0x0fU]);
    }
    return nonce;
}

struct preset_startup {
    std::unique_ptr<glove::net::credentialed_endpoint> endpoint;
    std::optional<glove::container::bridge_endpoint_settings> bridge;
    std::vector<std::string> environment;
};

// Start the mediated reverse endpoint for `--agent <preset>` and compute the
// environment that steers the client at it. The real provider secret is read
// only here, on the host, and is never placed in the child environment.
auto start_agent_preset(const options& opts, const std::shared_ptr<glove::audit::sink>& sink)
    -> std::expected<preset_startup, std::string> {
    preset_startup startup;
    if (!opts.agent_preset) {
        return startup;
    }
    auto definition = preset_definition_for(*opts.agent_preset);
    if (!definition) {
        return std::unexpected(
            std::string{"unknown --agent preset '"} + *opts.agent_preset +
            "'; expected claude-code, codex, or pi"
        );
    }
    // The sandbox exposes exactly one loopback bridge destination, so a
    // credentialed endpoint cannot coexist with raw CONNECT egress. Allowing
    // both would also let the agent bypass injection and inspection.
    if (!opts.egress.empty()) {
        return std::unexpected(
            std::string{"--agent "} + std::string{definition->label} +
            " cannot be combined with --egress-allow: the sandbox has one loopback bridge "
            "destination, and a credentialed upstream must not also be reachable over raw "
            "CONNECT egress"
        );
    }
    const std::string api_key_env{definition->api_key_env};
    // Reject host-credential-shaped selections. `--env` cannot smuggle a real
    // provider secret or a base-URL override past the mediated endpoint.
    for (const std::string_view name : opts.environment_names) {
        for (const std::string_view reserved : {
                 std::string_view{"ANTHROPIC_API_KEY"},
                 std::string_view{"ANTHROPIC_AUTH_TOKEN"},
                 std::string_view{"ANTHROPIC_BASE_URL"},
                 std::string_view{"OPENAI_API_KEY"},
                 std::string_view{"OPENAI_BASE_URL"},
             }) {
            if (name == reserved) {
                return std::unexpected(
                    std::string{"--env "} + std::string{name} +
                    " cannot be combined with "
                    "--agent: the mediated endpoint owns provider credentials and base URLs"
                );
            }
        }
    }
    const char* secret = std::getenv(api_key_env.c_str());
    if (secret == nullptr || *secret == '\0') {
        return std::unexpected(
            std::string{"--agent "} + std::string{definition->label} +
            " requires the host environment variable " + api_key_env
        );
    }
    auto nonce = random_session_nonce();
    if (!nonce) {
        return std::unexpected(nonce.error());
    }

    auto endpoint_options =
        detail::make_provider_endpoint_options(definition->surface, std::string{secret}, *nonce);
    if (!endpoint_options) {
        return std::unexpected(endpoint_options.error());
    }
    endpoint_options->on_event =
        [sink](const glove::net::endpoint_event& event) -> std::expected<void, std::string> {
        const std::string subject = event.method + " " + event.path;
        const auto status = event.allowed ? glove::mcp::tool_call_status::ok
                                          : glove::mcp::tool_call_status::invalid_arguments;
        if (auto audited =
                record(sink, glove::audit::action::egress, subject, status, event.detail);
            !audited) {
            return std::unexpected(audited.error());
        }
        return {};
    };

    auto endpoint = glove::net::start_credentialed_endpoint(std::move(*endpoint_options));
    if (!endpoint) {
        return std::unexpected(std::string{"credentialed endpoint: "} + endpoint.error());
    }
    auto base_url = (*endpoint)->base_url(definition->provider);
    if (!base_url) {
        return std::unexpected(base_url.error());
    }
    // The sandbox loopback bridge advertises the same port number in the
    // child's private network namespace, so one port describes both ends.
    startup.bridge = glove::container::bridge_endpoint_settings{
        .port = (*endpoint)->port(),
    };
    startup.environment.push_back(std::string{definition->base_url_env} + "=" + *base_url);
    startup.environment.push_back(api_key_env + "=" + *nonce);
    startup.endpoint = std::move(*endpoint);
    // Drop the real credential from this process's environment now that the
    // endpoint owns it. Otherwise it lingers and is inherited by every child
    // this process starts, including the optional herdr reporter, which is
    // spawned with ::environ.
    ::unsetenv(api_key_env.c_str());
    return startup;
}

class herdr_reporter final {
public:
    herdr_reporter(const herdr_reporter&) = delete;
    herdr_reporter& operator=(const herdr_reporter&) = delete;
    herdr_reporter(herdr_reporter&&) = delete;
    herdr_reporter& operator=(herdr_reporter&&) = delete;

    static auto create(bool enabled, std::string_view agent_name)
        -> std::expected<std::unique_ptr<herdr_reporter>, std::string> {
        if (!enabled) {
            return std::unique_ptr<herdr_reporter>{};
        }
        const char* herdr_env = std::getenv("HERDR_ENV");
        const char* pane_id = std::getenv("HERDR_PANE_ID");
        if (herdr_env == nullptr || std::string_view{herdr_env} != "1" || pane_id == nullptr ||
            *pane_id == '\0') {
            return std::unexpected(
                std::string{"--herdr requested but HERDR_ENV=1 and HERDR_PANE_ID are not set"}
            );
        }
        std::string bin = "herdr";
        if (const char* bin_path = std::getenv("HERDR_BIN_PATH");
            bin_path != nullptr && *bin_path != '\0') {
            bin = bin_path;
        }
        std::string normalized_name = std::filesystem::path{agent_name}.filename().string();
        if (normalized_name.empty()) {
            normalized_name = "agent";
        }
        auto reporter = std::unique_ptr<herdr_reporter>(
            new herdr_reporter(std::move(bin), pane_id, std::move(normalized_name))
        );
        reporter->report("working");
        return reporter;
    }

    ~herdr_reporter() {
        if (!pane_id_.empty()) {
            report("done");
            release();
        }
    }

    void report(std::string_view state) const {
        run_command({
            "pane",
            "report-agent",
            pane_id_,
            "--source",
            "glove:sandbox",
            "--agent",
            agent_name_,
            "--state",
            std::string{state},
        });
    }

    void release() const {
        run_command({
            "pane",
            "release-agent",
            pane_id_,
            "--source",
            "glove:sandbox",
            "--agent",
            agent_name_,
        });
    }

private:
    herdr_reporter(std::string bin, std::string pane_id, std::string agent_name)
        : bin_{std::move(bin)}, pane_id_{std::move(pane_id)}, agent_name_{std::move(agent_name)} {}

    void run_command(const std::vector<std::string>& args) const {
        std::vector<char*> c_args;
        c_args.reserve(args.size() + 2);
        c_args.push_back(const_cast<char*>(bin_.c_str()));
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);

        pid_t pid = 0;
        // Its own process group, so a signal aimed at glove (or a terminal
        // hangup) is not also delivered to the reporter.
        ::posix_spawnattr_t attr{};
        if (::posix_spawnattr_init(&attr) != 0) {
            std::fprintf(stderr, "glove: herdr spawn attributes could not be initialized\n");
            return;
        }
        static_cast<void>(::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP));
        static_cast<void>(::posix_spawnattr_setpgroup(&attr, 0));
        const int spawn_rc =
            ::posix_spawnp(&pid, bin_.c_str(), nullptr, &attr, c_args.data(), ::environ);
        ::posix_spawnattr_destroy(&attr);
        if (spawn_rc != 0) {
            std::fprintf(
                stderr, "glove: herdr report failed to spawn: %s\n", std::strerror(spawn_rc)
            );
            return;
        }

        // Report the state, but never block the agent on it. A hung herdr must
        // not hold up launch or teardown, so the wait is bounded and the child
        // is killed by process group if it overruns.
        constexpr auto reporter_timeout = std::chrono::milliseconds{5000};
        const auto deadline = std::chrono::steady_clock::now() + reporter_timeout;
        int status = 0;
        bool reaped = false;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto result = ::waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                reaped = true;
                break;
            }
            if (result < 0 && errno != EINTR) {
                break;
            }
            ::usleep(10'000);
        }
        if (!reaped) {
            std::fprintf(stderr, "glove: herdr command exceeded its deadline; killing it\n");
            static_cast<void>(::kill(-pid, SIGKILL));
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            std::fprintf(
                stderr, "glove: herdr command returned non-zero exit status (%d)\n", status
            );
        }
    }

    std::string bin_;
    std::string pane_id_;
    std::string agent_name_;
};

class socket_mcp_transport final : public glove::mcp::transport {
public:
    static constexpr std::size_t kMaxFrameBytes = 16U * 1024U * 1024U;

    socket_mcp_transport(int fd, const std::atomic<bool>& stopping) noexcept
        : fd_{fd}, stopping_{stopping} {}

    ~socket_mcp_transport() override {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }

    auto send(std::string_view frame) -> std::expected<void, std::string> override {
        std::string line{frame};
        line.push_back('\n');
        std::size_t sent = 0;
        while (sent < line.size()) {
            const ::ssize_t n = ::send(fd_, line.data() + sent, line.size() - sent, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"mcp socket write: "} + std::strerror(errno));
            }
            sent += static_cast<std::size_t>(n);
        }
        return {};
    }

    auto recv() -> std::expected<std::string, std::string> override {
        for (;;) {
            const auto nl = buffer_.find('\n');
            if (nl != std::string::npos) {
                std::string line = buffer_.substr(0, nl);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                buffer_.erase(0, nl + 1U);
                return line;
            }
            if (stopping_.load()) {
                return std::unexpected(std::string{"EOF"});
            }
            ::pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
            const int ready = ::poll(&pfd, 1, 100);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"mcp socket poll: "} + std::strerror(errno));
            }
            if (ready == 0) {
                continue;
            }
            std::array<char, 4096> chunk{};
            const ::ssize_t n = ::recv(fd_, chunk.data(), chunk.size(), 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(std::string{"mcp socket read: "} + std::strerror(errno));
            }
            if (n == 0) {
                if (!buffer_.empty()) {
                    std::string tail = std::move(buffer_);
                    buffer_.clear();
                    return tail;
                }
                return std::unexpected(std::string{"EOF"});
            }
            if (buffer_.size() + static_cast<std::size_t>(n) > kMaxFrameBytes) {
                return std::unexpected(std::string{"mcp socket frame exceeds 16 MiB limit"});
            }
            buffer_.append(chunk.data(), static_cast<std::size_t>(n));
        }
    }

private:
    int fd_ = -1;
    const std::atomic<bool>& stopping_;
    std::string buffer_;
};

class mcp_socket_bridge {
public:
    static auto start(
        const std::filesystem::path& sock_path,
        glove::kernel::registry& registry,
        std::shared_ptr<glove::policy::engine> policy,
        std::shared_ptr<glove::audit::sink> sink
    ) -> std::expected<std::unique_ptr<mcp_socket_bridge>, std::string> {
        if (sock_path.string().size() >= sizeof(::sockaddr_un{}.sun_path)) {
            return std::unexpected(std::string{"MCP socket path is too long"});
        }
#if defined(SOCK_CLOEXEC)
        const int listen_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
        const int listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
#endif
        if (listen_fd < 0) {
            return std::unexpected(std::string{"socket(AF_UNIX): "} + std::strerror(errno));
        }
        (void)::fcntl(listen_fd, F_SETFD, FD_CLOEXEC);
        ::unlink(sock_path.c_str());
        ::sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1U);
        if (::bind(listen_fd, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::chmod(sock_path.c_str(), 0600) != 0 || ::listen(listen_fd, 8) != 0) {
            const int saved = errno;
            (void)::close(listen_fd);
            (void)::unlink(sock_path.c_str());
            return std::unexpected(std::string{"bind/listen MCP socket: "} + std::strerror(saved));
        }
        return std::unique_ptr<mcp_socket_bridge>(new mcp_socket_bridge(
            listen_fd, sock_path, registry, std::move(policy), std::move(sink)
        ));
    }

    ~mcp_socket_bridge() {
        stopping_.store(true);
        if (worker_.joinable()) {
            worker_.join();
        }
        if (listen_fd_ >= 0) {
            (void)::close(listen_fd_);
            listen_fd_ = -1;
        }
        (void)::unlink(sock_path_.c_str());
    }

private:
    mcp_socket_bridge(
        int listen_fd,
        std::filesystem::path sock_path,
        glove::kernel::registry& registry,
        std::shared_ptr<glove::policy::engine> policy,
        std::shared_ptr<glove::audit::sink> sink
    )
        : listen_fd_{listen_fd},
          sock_path_{std::move(sock_path)},
          registry_{registry},
          policy_{std::move(policy)},
          sink_{std::move(sink)},
          worker_{[this] { serve_loop(); }} {}

    void serve_loop() {
        while (!stopping_.load()) {
            ::pollfd pfd{.fd = listen_fd_, .events = POLLIN, .revents = 0};
            const int ready = ::poll(&pfd, 1, 100);
            if (ready <= 0) {
                continue;
            }
            const int client_fd = ::accept(listen_fd_, nullptr, nullptr);
            if (client_fd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            (void)::fcntl(client_fd, F_SETFD, FD_CLOEXEC);
            socket_mcp_transport transport{client_fd, stopping_};
            glove::kernel::server::options server_options{
                .identity = {.name = "glove", .version = "0.0.1"},
                .policy = policy_,
                .audit = sink_,
            };
            glove::kernel::server server{transport, registry_, std::move(server_options)};
            (void)server.run();
        }
    }

    int listen_fd_ = -1;
    std::filesystem::path sock_path_;
    glove::kernel::registry& registry_;
    std::shared_ptr<glove::policy::engine> policy_;
    std::shared_ptr<glove::audit::sink> sink_;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
};

auto json_quote_string(std::string_view text) -> std::string {
    std::string out = "\"";
    static constexpr char kHex[] = "0123456789abcdef";
    for (const char ch : text) {
        switch (ch) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default: {
            const auto b = static_cast<unsigned char>(ch);
            if (b < 0x20U) {
                out += "\\u00";
                out.push_back(kHex[(b >> 4U) & 0x0FU]);
                out.push_back(kHex[b & 0x0FU]);
            } else {
                out.push_back(ch);
            }
            break;
        }
        }
    }
    out.push_back('"');
    return out;
}

auto resolve_self_executable() -> std::optional<std::filesystem::path> {
    std::error_code ec;
#if defined(__APPLE__)
    std::uint32_t size = 0;
    if (::_NSGetExecutablePath(nullptr, &size) != -1 || size == 0 || size > 64U * 1024U) {
        return std::nullopt;
    }
    std::vector<char> buf(size);
    if (::_NSGetExecutablePath(buf.data(), &size) != 0) {
        return std::nullopt;
    }
    auto canon = std::filesystem::canonical(buf.data(), ec);
    if (ec) {
        return std::nullopt;
    }
    return canon;
#else
    auto canon = std::filesystem::canonical("/proc/self/exe", ec);
    if (ec) {
        return std::nullopt;
    }
    return canon;
#endif
}

void write_guest_mcp_configs(
    const glove::container::profile& profile,
    const std::filesystem::path& glove_exe,
    const std::filesystem::path& sock_path
) noexcept {
    if (!profile.home_dir) {
        return;
    }
    std::error_code ec;
    const std::filesystem::path guest_home{*profile.home_dir};
    const std::string mcp_json = "{\n"
                                 "  \"mcpServers\": {\n"
                                 "    \"glove\": {\n"
                                 "      \"command\": " +
                                 json_quote_string(glove_exe.string()) +
                                 ",\n"
                                 "      \"args\": [\"mcp-bridge\", " +
                                 json_quote_string(sock_path.string()) +
                                 "],\n"
                                 "      \"directTools\": true\n"
                                 "    }\n"
                                 "  }\n"
                                 "}\n";
    for (const auto& rel : {
             std::filesystem::path{".pi"} / "agent" / "mcp.json",
             std::filesystem::path{".pi"} / "agent" / "mcp-adapter.json",
             std::filesystem::path{".gemini"} / "antigravity-cli" / "mcp_config.json",
             std::filesystem::path{".claude.json"},
         }) {
        const auto dst = guest_home / rel;
        std::filesystem::create_directories(dst.parent_path(), ec);
        std::ofstream out(dst, std::ios::binary | std::ios::trunc);
        if (out) {
            out << mcp_json;
            out.close();
            std::filesystem::permissions(
                dst,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                ec
            );
        }
    }
}

} // namespace

auto execute(const options& opts) -> std::expected<int, std::string> {
    if (opts.agent_argv.empty()) {
        return std::unexpected(std::string{"runner: agent_argv is required"});
    }
    auto runtime = private_runtime::create();
    if (!runtime) {
        return std::unexpected(runtime.error());
    }
    auto profile = prepare_profile(opts, runtime->root());
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto registry = build_registry(opts.upstreams);
    if (!registry) {
        return std::unexpected(registry.error());
    }
    auto audit_path = audit_destination(opts.audit_log, *profile);
    if (!audit_path) {
        return std::unexpected(audit_path.error());
    }
    const bool is_default_log = !opts.audit_log.has_value() && audit_path->has_value();
    auto sink = build_audit_sink(*audit_path, is_default_log);
    if (!sink) {
        return std::unexpected(sink.error());
    }
    std::shared_ptr<glove::policy::engine> policy = glove::policy::make_jsonpath_engine(
        {.allow = opts.allow,
         .deny = {},
         .prefix_rules = opts.prefix_rules,
         .default_decision = glove::policy::decision::deny}
    );
    auto proxy = start_egress(opts, *profile, *sink);
    if (!proxy) {
        return std::unexpected(proxy.error());
    }
    auto spawner = glove::container::make_default_spawner();
    if (!spawner) {
        return std::unexpected(std::string{"no platform spawner available"});
    }
    if (audit_path && *audit_path) {
        for (const auto& rule : profile->filesystem) {
            if (path_within(**audit_path, std::filesystem::path{rule.path})) {
                return std::unexpected(
                    std::string{"audit destination is exposed by final launch profile mount: '"} +
                    rule.path + "'"
                );
            }
        }
    }

    if (auto audited = record(*sink, glove::audit::action::agent_launch, opts.agent_argv.front());
        !audited) {
        return std::unexpected(std::string{"audit launch: "} + audited.error());
    }
    auto handle = spawner->spawn(*profile, opts.agent_argv);
    if (!handle) {
        return std::unexpected(std::string{"spawn: "} + handle.error());
    }
    glove::kernel::server::options server_options{
        .identity = {.name = "glove", .version = "0.0.1"},
        .policy = std::move(policy),
        .audit = *sink,
    };
    glove::kernel::server server{(*handle)->transport(), **registry, std::move(server_options)};
    if (auto ran = server.run(); !ran) {
        return std::unexpected(std::string{"kernel: "} + ran.error());
    }
    auto exit_code = (*handle)->wait();
    if (!exit_code) {
        return std::unexpected(std::string{"wait: "} + exit_code.error());
    }
    if (auto audited = record(
            *sink,
            glove::audit::action::agent_exit,
            std::to_string(*exit_code),
            *exit_code == 0 ? glove::mcp::tool_call_status::ok
                            : glove::mcp::tool_call_status::execution_error
        );
        !audited) {
        return std::unexpected(std::string{"audit exit: "} + audited.error());
    }
    return *exit_code;
}

auto exec(const options& opts) -> std::expected<int, std::string> {
    if (opts.agent_argv.empty()) {
        return std::unexpected(std::string{"runner: agent_argv is required"});
    }
    auto runtime = private_runtime::create();
    if (!runtime) {
        return std::unexpected(runtime.error());
    }
    auto profile = prepare_profile(opts, runtime->root());
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto audit_path = audit_destination(opts.audit_log, *profile);
    if (!audit_path) {
        return std::unexpected(audit_path.error());
    }
    const bool is_default_log = !opts.audit_log.has_value() && audit_path->has_value();
    auto sink = build_audit_sink(*audit_path, is_default_log);
    if (!sink) {
        return std::unexpected(sink.error());
    }
    auto proxy = start_egress(opts, *profile, *sink);
    if (!proxy) {
        return std::unexpected(proxy.error());
    }

    auto preset = start_agent_preset(opts, *sink);
    if (!preset) {
        return std::unexpected(preset.error());
    }
    if (preset->bridge) {
        profile->bridge_endpoint = *preset->bridge;
        profile->environment.insert(
            profile->environment.end(), preset->environment.begin(), preset->environment.end()
        );
        // Re-validate so the credentialed-endpoint/egress mutual exclusion and
        // environment rules are enforced on the exact launch profile.
        auto revalidated = glove::container::validate(*profile);
        if (!revalidated) {
            return std::unexpected(std::string{"profile: "} + revalidated.error());
        }
        *profile = std::move(*revalidated);
    } else if (!profile->proxy) {
        std::optional<std::uint16_t> target_port = opts.bridge_port;
        if (!target_port && opts.seed_guest_agent_home && profile->home_dir) {
            target_port = detect_loopback_port_in_models_json(
                std::filesystem::path{*profile->home_dir} / ".pi" / "agent" / "models.json"
            );
        }
        if (target_port && *target_port != 0) {
            profile->bridge_endpoint =
                glove::container::bridge_endpoint_settings{.port = *target_port};
            auto revalidated = glove::container::validate(*profile);
            if (!revalidated) {
                return std::unexpected(std::string{"profile: "} + revalidated.error());
            }
            *profile = std::move(*revalidated);
        }
    }

    auto reporter = herdr_reporter::create(opts.herdr, opts.agent_argv.front());
    if (!reporter) {
        return std::unexpected(reporter.error());
    }

    std::optional<private_runtime> mcp_runtime;
    std::unique_ptr<glove::kernel::registry> mcp_registry;
    std::unique_ptr<mcp_socket_bridge> mcp_bridge;
    if (!opts.upstreams.empty() || !opts.allow.empty() || !opts.prefix_rules.empty()) {
        auto created_mcp_dir = private_runtime::create();
        if (!created_mcp_dir) {
            return std::unexpected(created_mcp_dir.error());
        }
        mcp_runtime.emplace(std::move(*created_mcp_dir));
        auto built_reg = build_registry(opts.upstreams);
        if (!built_reg) {
            return std::unexpected(built_reg.error());
        }
        mcp_registry = std::move(*built_reg);
        std::vector<std::string> effective_allow = opts.allow;
        if (effective_allow.empty() && !opts.prefix_rules.empty()) {
            for (const auto& rule : opts.prefix_rules) {
                if (std::ranges::find(effective_allow, rule.tool_name) == effective_allow.end()) {
                    effective_allow.push_back(rule.tool_name);
                }
            }
        }
        const auto default_mcp_decision = (effective_allow.empty() && !opts.upstreams.empty())
                                              ? glove::policy::decision::allow
                                              : glove::policy::decision::deny;
        std::shared_ptr<glove::policy::engine> policy = glove::policy::make_jsonpath_engine(
            {.allow = std::move(effective_allow),
             .deny = {},
             .prefix_rules = opts.prefix_rules,
             .default_decision = default_mcp_decision}
        );
        const auto sock_path = mcp_runtime->root() / "glove-mcp.sock";
        auto started_bridge =
            mcp_socket_bridge::start(sock_path, *mcp_registry, std::move(policy), *sink);
        if (!started_bridge) {
            return std::unexpected(started_bridge.error());
        }
        mcp_bridge = std::move(*started_bridge);
        profile->allow_loopback_listen = true;
        profile->filesystem.push_back({.path = mcp_runtime->root().string(), .writable = false});
        profile->environment.push_back("GLOVE_MCP_SOCKET=" + sock_path.string());
        if (auto self_exe = resolve_self_executable(); self_exe && self_exe->has_parent_path()) {
            const std::string self_dir = self_exe->parent_path().string();
            bool covered = false;
            for (const auto& rule : profile->filesystem) {
                if (path_within(self_exe->parent_path(), std::filesystem::path{rule.path})) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                profile->filesystem.push_back({.path = self_dir, .writable = false});
            }
            write_guest_mcp_configs(*profile, *self_exe, sock_path);
        }
        auto revalidated = glove::container::validate(*profile);
        if (!revalidated) {
            return std::unexpected(std::string{"profile: "} + revalidated.error());
        }
        *profile = std::move(*revalidated);
    }

    if (audit_path && *audit_path) {
        for (const auto& rule : profile->filesystem) {
            if (path_within(**audit_path, std::filesystem::path{rule.path})) {
                return std::unexpected(
                    std::string{"audit destination is exposed by final launch profile mount: '"} +
                    rule.path + "'"
                );
            }
        }
    }

    if (auto audited = record(*sink, glove::audit::action::agent_launch, opts.agent_argv.front());
        !audited) {
        return std::unexpected(std::string{"audit launch: "} + audited.error());
    }
    std::mutex escape_audit_mutex;
    std::optional<std::string> escape_audit_error;
    auto exit_code = glove::container::exec_contained(
        *profile,
        opts.agent_argv,
        [sink = *sink,
         &escape_audit_mutex,
         &escape_audit_error](const glove::container::containment_escape_event& escape_event) {
            const std::string detail = escape_event.mechanism + ":" + escape_event.detail +
                                       " (pid=" + std::to_string(escape_event.pid) + ")";
            if (auto audited = record(
                    sink,
                    glove::audit::action::control,
                    "seccomp_escape_detected",
                    glove::mcp::tool_call_status::execution_error,
                    detail
                );
                !audited) {
                const std::scoped_lock lock{escape_audit_mutex};
                if (!escape_audit_error) {
                    escape_audit_error = audited.error();
                }
            }
            static_cast<void>(std::fprintf(
                stderr,
                "glove security: terminated sandbox after escape syscall '%s' (pid %d)\n",
                escape_event.detail.c_str(),
                static_cast<int>(escape_event.pid)
            ));
        }
    );
    if (escape_audit_error) {
        return std::unexpected(std::string{"audit seccomp escape: "} + *escape_audit_error);
    }
    if (!exit_code) {
        return std::unexpected(exit_code.error());
    }
    if (auto audited = record(
            *sink,
            glove::audit::action::agent_exit,
            std::to_string(*exit_code),
            *exit_code == 0 ? glove::mcp::tool_call_status::ok
                            : glove::mcp::tool_call_status::execution_error
        );
        !audited) {
        return std::unexpected(std::string{"audit exit: "} + audited.error());
    }
    return *exit_code;
}

} // namespace glove::run
