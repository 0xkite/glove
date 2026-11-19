#include "glove/run/launch_profile.hpp"

#include "glove/host/config.hpp"
#include "glove/host/runtime_policy.hpp"

#include "../host/runtime_snapshot.hpp"

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <ranges>
#include <system_error>
#include <utility>

namespace glove::run {
namespace {

auto system_message(int error_number) -> std::string {
    return std::error_code{error_number, std::generic_category()}.message();
}

auto read_profile_text_impl(const std::filesystem::path& path)
    -> std::expected<std::string, std::string> {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        const int error = errno;
        if (error == ENOENT) {
            return std::unexpected("no profile at " + path.string());
        }
        if (error == ELOOP) {
            return std::unexpected("profile is a symbolic link: " + path.string());
        }
        return std::unexpected("cannot open " + path.string() + ": " + system_message(error));
    }

    struct closer {
        int fd;

        explicit closer(int descriptor) : fd{descriptor} {}

        closer(const closer&) = delete;
        auto operator=(const closer&) -> closer& = delete;
        closer(closer&&) = delete;
        auto operator=(closer&&) -> closer& = delete;

        ~closer() { (void)::close(fd); }
    } const guard{fd};
    struct stat metadata{};
    if (::fstat(fd, &metadata) != 0) {
        return std::unexpected("cannot inspect " + path.string() + ": " + system_message(errno));
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid() || metadata.st_nlink != 1) {
        return std::unexpected(
            "profile must be a regular single-link file owned by you: " + path.string()
        );
    }
    if ((metadata.st_mode & 07777U) != 0600U) {
        return std::unexpected("profile must have mode 0600 (chmod 600 " + path.string() + ")");
    }
    if (metadata.st_size <= 0 || std::cmp_greater(metadata.st_size, max_launch_profile_bytes)) {
        return std::unexpected("profile is empty or larger than 64 KiB: " + path.string());
    }
    std::string contents(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < contents.size()) {
        const auto got = ::read(fd, contents.data() + consumed, contents.size() - consumed);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return std::unexpected("profile changed while reading: " + path.string());
        }
        consumed += static_cast<std::size_t>(got);
    }
    char extra = 0;
    if (::read(fd, &extra, 1) != 0) {
        return std::unexpected("profile changed while reading: " + path.string());
    }
    return contents;
}

auto normal_form(const std::filesystem::path& path) -> std::filesystem::path {
    auto normal = path.lexically_normal();
    while (!normal.has_filename() && normal != normal.root_path()) {
        normal = normal.parent_path();
    }
    return normal;
}

auto contains(const std::filesystem::path& outer, const std::filesystem::path& inner) -> bool {
    const auto [end_outer, end_inner] = std::ranges::mismatch(outer, inner);
    static_cast<void>(end_inner);
    return end_outer == outer.end();
}

auto forms(const std::filesystem::path& path) -> std::vector<std::filesystem::path> {
    std::vector<std::filesystem::path> out{normal_form(path)};
    std::error_code ec;
    if (const auto canonical = std::filesystem::weakly_canonical(path, ec); !ec) {
        out.push_back(normal_form(canonical));
    }
    return out;
}

} // namespace

auto launch_profile_directory() -> std::expected<std::filesystem::path, std::string> {
    auto directories = glove::host::resolve_directories(glove::host::current_environment());
    if (!directories) {
        return std::unexpected(directories.error());
    }
    std::error_code ec;
    const auto config = std::filesystem::weakly_canonical(directories->config, ec);
    if (ec) {
        return std::unexpected("cannot resolve " + directories->config.string());
    }
    auto directory = normal_form(config / "profiles");
    if (auto ok = glove::host::snapshot::ensure_protected_directory(directory, true); !ok) {
        return std::unexpected(directory.string() + ": " + ok.error());
    }
    return directory;
}

auto launch_profile_path(std::string_view name)
    -> std::expected<std::filesystem::path, std::string> {
    if (!glove::host::is_valid_policy_name(name)) {
        return std::unexpected(
            "invalid profile name '" + std::string{name} +
            "' (letters, digits, '-', '_', '.'; at most 64)"
        );
    }
    auto directory = launch_profile_directory();
    if (!directory) {
        return std::unexpected(directory.error());
    }
    return *directory / (std::string{name} + ".yaml");
}

auto read_launch_profile_text(const std::filesystem::path& path)
    -> std::expected<std::string, std::string> {
    return read_profile_text_impl(path);
}

auto load_launch_profile_file(const std::filesystem::path& path)
    -> std::expected<launch_profile, std::string> {
    auto contents = read_profile_text_impl(path);
    if (!contents) {
        return std::unexpected(contents.error());
    }
    auto parsed = parse_launch_profile(*contents);
    if (!parsed) {
        return std::unexpected(path.string() + ": " + parsed.error());
    }
    return parsed;
}

auto load_launch_profile(std::string_view name) -> std::expected<launch_profile, std::string> {
    auto path = launch_profile_path(name);
    if (!path) {
        return std::unexpected(path.error());
    }
    auto loaded = load_launch_profile_file(*path);
    if (!loaded && loaded.error().starts_with("no profile at ")) {
        return std::unexpected(
            "no profile '" + std::string{name} + "' (create it with: glove profile new " +
            std::string{name} + ")"
        );
    }
    return loaded;
}

namespace {

// Profile entries first, then the command line's, for every list option.
void merge_profile_lists(const launch_profile& profile, const options& cli, options& out) {
    out.environment_names.clear();
    out.environment_values.clear();
    for (const auto& entry : profile.env) {
        if (entry.value) {
            out.environment_values.push_back({.name = entry.name, .value = *entry.value});
        } else {
            out.environment_names.push_back(entry.name);
        }
    }
    out.environment_names.insert(
        out.environment_names.end(), cli.environment_names.begin(), cli.environment_names.end()
    );
    out.environment_values.insert(
        out.environment_values.end(), cli.environment_values.begin(), cli.environment_values.end()
    );
    out.egress = profile.egress;
    out.egress.insert(out.egress.end(), cli.egress.begin(), cli.egress.end());
    out.upstreams = profile.mcp;
    out.upstreams.insert(out.upstreams.end(), cli.upstreams.begin(), cli.upstreams.end());
    out.allow = profile.allow;
    out.allow.insert(out.allow.end(), cli.allow.begin(), cli.allow.end());
    out.prefix_rules = profile.allow_arg;
    out.prefix_rules.insert(
        out.prefix_rules.end(), cli.prefix_rules.begin(), cli.prefix_rules.end()
    );
}

} // namespace

auto apply_launch_profile(
    const launch_profile& profile, const options& cli, const std::filesystem::path& home
) -> std::expected<options, std::string> {
    const auto expand =
        [&home](const std::string& path) -> std::expected<std::string, std::string> {
        if (path != "~" && !path.starts_with("~/")) {
            return path;
        }
        if (!home.is_absolute() || home == home.root_path()) {
            return std::unexpected("cannot expand '" + path + "': home directory is unknown");
        }
        return path == "~" ? home.string() : (home / path.substr(2)).string();
    };
    options out = cli;
    if (!cli.workspace && profile.workspace) {
        auto workspace = expand(*profile.workspace);
        if (!workspace) {
            return std::unexpected(workspace.error());
        }
        out.workspace = std::filesystem::path{*workspace};
    }
    if (!cli.agent_preset && profile.agent) {
        out.agent_preset = profile.agent;
    }
    if (!cli.bridge_port && profile.bridge_port) {
        out.bridge_port = profile.bridge_port;
    }
    const auto paths = [&expand](
                           const std::vector<std::string>& from,
                           const std::vector<std::string>& extra,
                           std::vector<std::string>& into
                       ) -> std::expected<void, std::string> {
        into.clear();
        for (const auto& path : from) {
            auto expanded = expand(path);
            if (!expanded) {
                return std::unexpected(expanded.error());
            }
            into.push_back(std::move(*expanded));
        }
        into.insert(into.end(), extra.begin(), extra.end());
        return {};
    };
    if (auto ok = paths(profile.read, cli.readable, out.readable); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = paths(profile.write, cli.writable, out.writable); !ok) {
        return std::unexpected(ok.error());
    }
    merge_profile_lists(profile, cli, out);
    return out;
}

auto invoking_user_home() -> std::filesystem::path {
    std::vector<char> buffer(16384);
    struct ::passwd account{};
    struct ::passwd* found = nullptr;
    if (::getpwuid_r(::geteuid(), &account, buffer.data(), buffer.size(), &found) != 0 ||
        found == nullptr || found->pw_dir == nullptr || found->pw_dir[0] != '/') {
        return {};
    }
    return std::filesystem::path{found->pw_dir};
}

auto protected_glove_roots() -> std::vector<std::filesystem::path> {
    std::vector<std::filesystem::path> roots;
    const auto add = [&roots](const std::filesystem::path& root) {
        for (auto&& form : forms(root)) {
            if (form.is_absolute() && form != form.root_path() &&
                std::ranges::find(roots, form) == roots.end()) {
                roots.push_back(std::move(form));
            }
        }
    };
    if (auto directories = glove::host::resolve_directories(glove::host::current_environment())) {
        add(directories->config);
        add(directories->state);
    }
    // The defaults under the account's home as well, in case XDG variables
    // point elsewhere for this invocation.
    if (const auto home = invoking_user_home(); !home.empty()) {
        add(home / ".config" / "glove");
        add(home / ".local" / "state" / "glove");
    }
    return roots;
}

auto refuse_glove_root_exposure(
    std::span<const std::string> exposed, std::span<const std::filesystem::path> roots
) -> std::expected<void, std::string> {
    for (const auto& path : exposed) {
        for (const auto& form : forms(std::filesystem::path{path})) {
            for (const auto& root : roots) {
                if (contains(root, form) || contains(form, root)) {
                    return std::unexpected(
                        "'" + path + "' would expose glove's own configuration or state (" +
                        root.string() +
                        ") to the sandbox; profiles, policy, and audit records stay host-only"
                    );
                }
            }
        }
    }
    return {};
}

} // namespace glove::run
