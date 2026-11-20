#include "profile_cli.hpp"

#include "glove/run/launch_profile.hpp"

#include "secret_resolve.hpp"

#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

extern char** environ; // NOLINT(readability-redundant-declaration)

namespace glove::run {
namespace {

template<typename T> using result = std::expected<T, std::string>;

void usage() {
    std::fprintf(
        stderr,
        "usage: glove profile <command> [<name>]\n"
        "\n"
        "Launch profiles live in <XDG_CONFIG_HOME>/glove/profiles/<name>.yaml\n"
        "(owner-only, mode 0600). Glove reads them on the host; the sandbox can\n"
        "never read or write them. Use one with `glove exec|run|shell --profile <name>`;\n"
        "flags given on the command line add to the profile.\n"
        "\n"
        "commands:\n"
        "  list                 list profiles and whether each one loads\n"
        "  new <name>           create a profile from a commented template\n"
        "  edit <name>          edit in $VISUAL or $EDITOR; saved only if it validates\n"
        "  show <name|path>     print the profile as glove reads it\n"
        "  check <name|path>    exit 1 if glove would refuse to launch with it\n"
        "  path [<name>]        print the profile directory, or one profile's path\n"
    );
}

auto system_message(int error_number) -> std::string {
    return std::error_code{error_number, std::generic_category()}.message();
}

auto fail(const std::string& message) -> int {
    std::fprintf(stderr, "glove profile: %s\n", message.c_str());
    return 1;
}

// A NAME, or a PATH when the argument contains '/'.
auto load_reference(std::string_view reference) -> result<launch_profile> {
    if (reference.contains('/')) {
        return load_launch_profile_file(std::filesystem::path{reference});
    }
    return load_launch_profile(reference);
}

auto write_all(int fd, std::string_view data) -> bool {
    while (!data.empty()) {
        const auto wrote = ::write(fd, data.data(), data.size());
        if (wrote < 0 && errno == EINTR) {
            continue;
        }
        if (wrote <= 0) {
            return false;
        }
        data.remove_prefix(static_cast<std::size_t>(wrote));
    }
    return true;
}

// Reads a file the editor may have replaced: it must still be a regular,
// single-link file owned by us. Restores mode 0600 before reading.
auto read_edited(const std::filesystem::path& path) -> result<std::string> {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected("cannot reopen " + path.string() + ": " + system_message(errno));
    }
    std::string contents;
    struct stat metadata{};
    bool ok = ::fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
              metadata.st_uid == ::geteuid() && metadata.st_nlink == 1 && ::fchmod(fd, 0600) == 0;
    while (ok) {
        std::array<char, 4096> buffer{};
        const auto got = ::read(fd, buffer.data(), buffer.size());
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            ok = got == 0;
            break;
        }
        contents.append(buffer.data(), static_cast<std::size_t>(got));
        if (contents.size() > max_launch_profile_bytes) {
            ::close(fd);
            return std::unexpected(std::string{"edited profile is larger than 64 KiB"});
        }
    }
    ::close(fd);
    if (!ok) {
        return std::unexpected("edited file is no longer a private regular file: " + path.string());
    }
    return contents;
}

auto run_editor(const std::filesystem::path& path) -> result<void> {
    const char* editor = std::getenv("VISUAL");
    if (editor == nullptr || *editor == '\0') {
        editor = std::getenv("EDITOR");
    }
    const std::string command =
        std::string{editor != nullptr && *editor != '\0' ? editor : "vi"} + " \"$1\"";
    std::vector<std::string> argv{"/bin/sh", "-c", command, "glove-profile-edit", path.string()};
    std::vector<char*> raw;
    raw.reserve(argv.size() + 1);
    for (auto& arg : argv) {
        raw.push_back(arg.data());
    }
    raw.push_back(nullptr);
    ::pid_t child = 0;
    if (const int error = ::posix_spawn(&child, "/bin/sh", nullptr, nullptr, raw.data(), environ);
        error != 0) {
        return std::unexpected("cannot start the editor: " + system_message(error));
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return std::unexpected("cannot wait for the editor: " + system_message(errno));
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::unexpected(std::string{"the editor exited with an error"});
    }
    return {};
}

auto ask_again() -> bool {
    if (::isatty(STDIN_FILENO) != 1) {
        return false;
    }
    std::fprintf(stderr, "edit again? [Y/n] ");
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        return false;
    }
    return answer.empty() || answer == "y" || answer == "Y" || answer == "yes";
}

auto sync_directory(const std::filesystem::path& directory) -> void {
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) {
        (void)::fsync(fd);
        (void)::close(fd);
    }
}

auto command_new(std::string_view name) -> int {
    auto path = launch_profile_path(name);
    if (!path) {
        return fail(path.error());
    }
    const int fd =
        ::open(path->c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return fail(
            errno == EEXIST
                ? "profile '" + std::string{name} + "' already exists: " + path->string()
                : "cannot create " + path->string() + ": " + system_message(errno)
        );
    }
    const bool written =
        ::fchmod(fd, 0600) == 0 && write_all(fd, launch_profile_template()) && ::fsync(fd) == 0;
    (void)::close(fd);
    if (!written) {
        std::error_code ignored;
        std::filesystem::remove(*path, ignored);
        return fail("cannot write " + path->string());
    }
    sync_directory(path->parent_path());
    std::printf("%s\n", path->c_str());
    return 0;
}

auto command_edit(std::string_view name) -> int {
    auto path = launch_profile_path(name);
    if (!path) {
        return fail(path.error());
    }
    std::error_code ec;
    const bool existed = std::filesystem::exists(std::filesystem::symlink_status(*path, ec));
    std::string original{launch_profile_template()};
    if (existed) {
        // The current file must pass the launch file checks (owner, mode,
        // one link, no symlink); only its contents may be wrong.
        auto contents = read_launch_profile_text(*path);
        if (!contents) {
            return fail(contents.error());
        }
        original = std::move(*contents);
    }
    std::string pattern =
        (path->parent_path() / ("." + std::string{name} + ".yaml.XXXXXX")).string();
    const int fd = ::mkstemp(pattern.data());
    if (fd < 0) {
        return fail("cannot create a temporary file: " + system_message(errno));
    }
    const std::filesystem::path temporary{pattern};
    const bool staged = ::fchmod(fd, 0600) == 0 && write_all(fd, original);
    (void)::close(fd);
    if (!staged) {
        std::filesystem::remove(temporary, ec);
        return fail("cannot write " + temporary.string());
    }
    for (;;) {
        if (auto edited = run_editor(temporary); !edited) {
            std::fprintf(
                stderr,
                "glove profile: %s; your edit is kept at %s\n",
                edited.error().c_str(),
                temporary.c_str()
            );
            return 1;
        }
        auto contents = read_edited(temporary);
        if (!contents) {
            return fail(contents.error());
        }
        if (existed && *contents == original) {
            std::filesystem::remove(temporary, ec);
            std::printf("unchanged: %s\n", path->c_str());
            return 0;
        }
        auto parsed = parse_launch_profile(*contents);
        if (parsed) {
            if (::rename(temporary.c_str(), path->c_str()) != 0) {
                return fail("cannot save " + path->string() + ": " + system_message(errno));
            }
            sync_directory(path->parent_path());
            std::printf("saved: %s\n", path->c_str());
            return 0;
        }
        std::fprintf(stderr, "glove profile: not saved: %s\n", parsed.error().c_str());
        if (!ask_again()) {
            std::fprintf(stderr, "glove profile: your edit is kept at %s\n", temporary.c_str());
            return 1;
        }
    }
}

auto command_check(std::string_view reference) -> int {
    auto profile = load_reference(reference);
    if (!profile) {
        return fail(profile.error());
    }
    auto applied = apply_launch_profile(*profile, options{}, invoking_user_home());
    if (!applied) {
        return fail(applied.error());
    }
    std::vector<std::string> exposed = applied->readable;
    exposed.insert(exposed.end(), applied->writable.begin(), applied->writable.end());
    if (applied->workspace) {
        exposed.push_back(applied->workspace->string());
    }
    if (auto refused = refuse_glove_root_exposure(exposed, protected_glove_roots()); !refused) {
        return fail(refused.error());
    }
    for (const auto& path : exposed) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) &&
            (!applied->workspace || path != applied->workspace->string())) {
            return fail("path does not exist: " + path);
        }
    }
    if (applied->provider_secret) {
        if (!applied->agent_preset) {
            return fail("secrets.provider needs an agent");
        }
        // Resolve now so a wrong reference fails here, not at launch. The
        // value is discarded and never printed.
        if (auto secret =
                detail::resolve_secret(*applied->provider_secret, invoking_user_home(), exposed);
            !secret) {
            return fail(secret.error());
        }
    }
    std::printf("ok\n");
    return 0;
}

auto command_list() -> int {
    auto directory = launch_profile_directory();
    if (!directory) {
        return fail(directory.error());
    }
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(*directory, ec)) {
        const auto& path = entry.path();
        if (path.extension() == ".yaml" && !path.filename().string().starts_with('.')) {
            files.push_back(path);
        }
    }
    if (ec) {
        return fail("cannot list " + directory->string() + ": " + ec.message());
    }
    std::ranges::sort(files);
    std::printf("profiles (%s):\n", directory->c_str());
    if (files.empty()) {
        std::printf("  (none; create one with: glove profile new <name>)\n");
    }
    for (const auto& path : files) {
        const auto loaded = load_launch_profile_file(path);
        std::string status = "ok";
        if (!loaded) {
            const auto& error = loaded.error();
            status = "invalid: " + error.substr(0, error.find('\n'));
        }
        std::printf("  %-20s %s\n", path.stem().c_str(), status.c_str());
    }
    return 0;
}

} // namespace

auto profile_command(std::span<char* const> arguments) -> int {
    if (arguments.empty()) {
        usage();
        return 2;
    }
    const std::string_view command{arguments[0]};
    const auto argument =
        arguments.size() > 1 ? std::string_view{arguments[1]} : std::string_view{};
    if (command == "-h" || command == "--help" || command == "help") {
        usage();
        return 0;
    }
    if (arguments.size() > 2) {
        usage();
        return 2;
    }
    if (command == "list" && arguments.size() == 1) {
        return command_list();
    }
    if (command == "path") {
        if (argument.empty()) {
            auto directory = launch_profile_directory();
            if (!directory) {
                return fail(directory.error());
            }
            std::printf("%s\n", directory->c_str());
            return 0;
        }
        auto path = launch_profile_path(argument);
        if (!path) {
            return fail(path.error());
        }
        std::printf("%s\n", path->c_str());
        return 0;
    }
    if (argument.empty()) {
        usage();
        return 2;
    }
    if (command == "new") {
        return command_new(argument);
    }
    if (command == "edit") {
        return command_edit(argument);
    }
    if (command == "check") {
        return command_check(argument);
    }
    if (command == "show") {
        auto profile = load_reference(argument);
        if (!profile) {
            return fail(profile.error());
        }
        std::fputs(encode_launch_profile(*profile).c_str(), stdout);
        return 0;
    }
    usage();
    return 2;
}

} // namespace glove::run
