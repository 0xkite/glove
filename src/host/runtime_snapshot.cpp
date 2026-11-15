#include "runtime_snapshot.hpp"

#include "glove/container/digest.hpp"
#include "glove/detail/symlink_acl.hpp"

#include "dependency_command.hpp"
#include "snapshot_cleanup.hpp"
#include "snapshot_copy.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

namespace glove::host::snapshot {

namespace {

auto valid_formula_name(std::string_view value) noexcept -> bool {
    return !value.empty() && value.size() <= 128U &&
           std::ranges::all_of(value, [](unsigned char byte) {
               return std::isalnum(byte) != 0 || byte == '@' || byte == '+' || byte == '-' ||
                      byte == '_' || byte == '.';
           });
}

} // namespace

auto homebrew_keg_for(const std::filesystem::path& path) -> std::optional<homebrew_keg> {
    std::filesystem::path prefix;
    auto component = path.begin();
    for (; component != path.end() && *component != "Cellar"; ++component) {
        prefix /= *component;
    }
    if (component == path.end()) {
        return std::nullopt;
    }
    ++component;
    if (component == path.end()) {
        return std::nullopt;
    }
    const std::string formula = component->string();
    ++component;
    if (!valid_formula_name(formula) || component == path.end()) {
        return std::nullopt;
    }
    return homebrew_keg{
        .prefix = prefix,
        .formula = formula,
        .root = prefix / "Cellar" / formula / *component,
    };
}

auto append_homebrew_runtime_closure(
    const homebrew_keg& interpreter,
    std::vector<std::filesystem::path>& paths,
    bool allow_dependency_commands
) -> result<void> {
    if (!allow_dependency_commands) {
        return std::unexpected(
            std::string{"Homebrew dependency closure requires executing brew; dry-run planning "
                        "does not execute dependency commands"}
        );
    }
    const auto brew = interpreter.prefix / "bin" / "brew";
    std::error_code error;
    const auto canonical_brew = std::filesystem::canonical(brew, error);
    if (error) {
        return std::unexpected("resolve Homebrew dependency tool: " + error.message());
    }
    auto dependencies = detail::capture_dependency_command(
        canonical_brew, {"deps", "--installed", "--formula", interpreter.formula}
    );
    if (!dependencies) {
        return std::unexpected(dependencies.error());
    }
    paths.push_back(interpreter.root);
    std::istringstream lines{*dependencies};
    for (std::string formula; std::getline(lines, formula);) {
        if (!valid_formula_name(formula)) {
            return std::unexpected(std::string{"Homebrew returned an invalid dependency name"});
        }
        const auto dependency_link = interpreter.prefix / "opt" / formula;
        const auto dependency = std::filesystem::canonical(dependency_link, error);
        if (error) {
            return std::unexpected(
                "resolve Homebrew dependency " + formula + ": " + error.message()
            );
        }
        const auto keg = homebrew_keg_for(dependency);
        if (!keg) {
            return std::unexpected(
                "Homebrew dependency does not resolve to one immutable keg: " + formula
            );
        }
        paths.push_back(keg->root);
    }
    return {};
}

auto minimise_roots(std::vector<std::filesystem::path> paths)
    -> std::vector<std::filesystem::path> {
    std::ranges::sort(paths);
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    std::vector<std::filesystem::path> roots;
    for (const auto& candidate : paths) {
        if (std::ranges::any_of(roots, [&](const auto& root) {
                return path_within(candidate, root);
            })) {
            continue;
        }
        std::erase_if(roots, [&](const auto& root) { return path_within(root, candidate); });
        roots.push_back(candidate);
    }
    std::ranges::sort(roots);
    return roots;
}

constexpr std::uint64_t max_snapshot_bytes = std::uint64_t{2} * 1024U * 1024U * 1024U;
constexpr std::size_t max_snapshot_entries = 200'000U;

auto append_snapshot_file_digest(
    const std::filesystem::path& path,
    std::string_view relative,
    std::string& manifest,
    std::uint64_t& total_bytes
) -> result<void> {
    // Discovery trees can change between enumeration and open. A replacement
    // FIFO must fail the descriptor type check instead of blocking setup.
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return std::unexpected(system_error("open harness snapshot file"));
    }
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0) {
        const auto error = system_error("inspect harness snapshot file");
        (void)::close(descriptor);
        return std::unexpected(error);
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_size < 0 || metadata.st_nlink != 1) {
        (void)::close(descriptor);
        return std::unexpected(std::string{"harness snapshot requires single-link regular files"});
    }
    const auto size = static_cast<std::uint64_t>(metadata.st_size);
    if (size > max_snapshot_bytes || total_bytes > max_snapshot_bytes - size) {
        (void)::close(descriptor);
        return std::unexpected(std::string{"harness snapshot exceeds the 2 GiB safety limit"});
    }
    auto digest = container::sha256_fd_hex(descriptor, std::max<std::uint64_t>(size, 1U));
    const int close_result = ::close(descriptor);
    if (!digest || close_result != 0) {
        return std::unexpected(
            digest ? system_error("close harness snapshot file")
                   : "hash harness snapshot file: " + digest.error()
        );
    }
    total_bytes += size;
    manifest.append("f\0", 2);
    manifest.append(relative);
    manifest.push_back('\0');
    manifest.append((metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 ? "x" : "-");
    manifest.push_back('\0');
    manifest.append(std::to_string(size));
    manifest.push_back('\0');
    manifest.append(*digest);
    manifest.push_back('\0');
    return {};
}

auto snapshot_tree_digest(
    const std::filesystem::path& root, std::uint64_t* logical_bytes, std::uint64_t* entry_count
) -> result<std::string> {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root, error);
    if (error) {
        return std::unexpected("inspect harness snapshot root: " + error.message());
    }
    std::string manifest;
    std::uint64_t total_bytes = 0;
    std::uint64_t total_entries = 0;
    if (std::filesystem::is_regular_file(status)) {
        if (auto appended =
                append_snapshot_file_digest(root, root.filename().string(), manifest, total_bytes);
            !appended) {
            return std::unexpected(appended.error());
        }
        total_entries = 1;
    } else if (std::filesystem::is_directory(status)) {
        std::vector<std::filesystem::path> entries;
        for (std::filesystem::recursive_directory_iterator
                 iterator{root, std::filesystem::directory_options::none, error},
             end;
             iterator != end;
             iterator.increment(error)) {
            if (error) {
                return std::unexpected("enumerate harness snapshot: " + error.message());
            }
            if (entries.size() >= max_snapshot_entries) {
                return std::unexpected(
                    std::string{"harness snapshot exceeds the 200000 entry safety limit"}
                );
            }
            entries.push_back(iterator->path());
        }
        total_entries = static_cast<std::uint64_t>(entries.size());
        std::ranges::sort(entries, [&](const auto& left, const auto& right) {
            return left.lexically_relative(root).generic_string() <
                   right.lexically_relative(root).generic_string();
        });
        const auto canonical_root = std::filesystem::canonical(root, error);
        if (error) {
            return std::unexpected("canonicalize harness snapshot root: " + error.message());
        }
        for (const auto& entry : entries) {
            const auto relative = entry.lexically_relative(root).generic_string();
            const auto entry_status = std::filesystem::symlink_status(entry, error);
            if (error) {
                return std::unexpected("inspect harness snapshot entry: " + error.message());
            }
            if (std::filesystem::is_directory(entry_status)) {
                manifest.append("d\0", 2);
                manifest.append(relative);
                manifest.push_back('\0');
            } else if (std::filesystem::is_regular_file(entry_status)) {
                if (auto appended =
                        append_snapshot_file_digest(entry, relative, manifest, total_bytes);
                    !appended) {
                    return std::unexpected(appended.error());
                }
            } else if (std::filesystem::is_symlink(entry_status)) {
                const auto target = std::filesystem::read_symlink(entry, error);
                if (error || target.is_absolute()) {
                    return std::unexpected(
                        std::string{"harness snapshot contains an unsafe symbolic link"}
                    );
                }
                const auto resolved = std::filesystem::canonical(entry, error);
                if (error || !path_within(resolved, canonical_root)) {
                    return std::unexpected(
                        std::string{"harness snapshot symbolic link escapes its closure"}
                    );
                }
                manifest.append("l\0", 2);
                manifest.append(relative);
                manifest.push_back('\0');
                manifest.append(target.generic_string());
                manifest.push_back('\0');
            } else {
                return std::unexpected(
                    std::string{"harness snapshot contains an unsupported special file"}
                );
            }
        }
    } else {
        return std::unexpected(std::string{"harness snapshot root must be a file or directory"});
    }
    const auto bytes = std::span{
        reinterpret_cast<const unsigned char*>(manifest.data()),
        manifest.size(),
    };
    auto digest = container::sha256_hex(bytes);
    if (!digest) {
        return std::unexpected(std::string{"hash harness snapshot manifest"});
    }
    if (logical_bytes != nullptr) {
        *logical_bytes = total_bytes;
    }
    if (entry_count != nullptr) {
        *entry_count = total_entries;
    }
    return *digest;
}

auto package_root_for(const std::filesystem::path& source) -> std::filesystem::path {
    std::error_code error;
    for (auto current = source.parent_path(); current != current.root_path();
         current = current.parent_path()) {
        const auto manifest = current / "package.json";
        if (std::filesystem::is_regular_file(manifest, error) && !error) {
            return current;
        }
        error.clear();
    }
    return source;
}

auto read_runtime_shebang(const std::filesystem::path& source)
    -> result<std::optional<std::vector<std::string>>> {
    const int descriptor = ::open(source.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return std::unexpected(system_error("open harness interpreter directive"));
    }

    struct close_descriptor {
        explicit close_descriptor(int descriptor_value) : value{descriptor_value} {}

        close_descriptor(const close_descriptor&) = delete;
        auto operator=(const close_descriptor&) -> close_descriptor& = delete;

        ~close_descriptor() { (void)::close(value); }

        int value;
    } owned{descriptor};
    struct stat before{};
    if (::fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1) {
        return std::unexpected(
            std::string{"harness directive source must be a single-link regular file"}
        );
    }
    const auto unchanged = [&]() -> bool {
        struct stat after{};
        struct stat named{};
        if (::fstat(descriptor, &after) != 0 || ::lstat(source.c_str(), &named) != 0) {
            return false;
        }
        const auto same = [&](const struct stat& value) {
            const bool identity = value.st_dev == before.st_dev && value.st_ino == before.st_ino &&
                                  value.st_mode == before.st_mode &&
                                  value.st_uid == before.st_uid && value.st_gid == before.st_gid &&
                                  value.st_nlink == before.st_nlink &&
                                  value.st_size == before.st_size;
#if defined(__APPLE__)
            return identity && value.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec &&
                   value.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec &&
                   value.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec &&
                   value.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec;
#else
            return identity && value.st_mtim.tv_sec == before.st_mtim.tv_sec &&
                   value.st_mtim.tv_nsec == before.st_mtim.tv_nsec &&
                   value.st_ctim.tv_sec == before.st_ctim.tv_sec &&
                   value.st_ctim.tv_nsec == before.st_ctim.tv_nsec;
#endif
        };
        return same(after) && same(named);
    };
    // Read only the marker for native binaries. A script gets at most its
    // bounded directive plus one newline; a FIFO replacement never blocks.
    std::array<char, 4097U> bytes{};
    std::size_t filled = 0;
    const auto read_prefix = [&](std::size_t limit) -> result<void> {
        while (filled < limit) {
            const auto count = ::pread(
                descriptor, bytes.data() + filled, limit - filled, static_cast<off_t>(filled)
            );
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < 0) {
                return std::unexpected(system_error("read harness interpreter directive"));
            }
            if (count == 0) {
                break;
            }
            filled += static_cast<std::size_t>(count);
        }
        return {};
    };
    if (auto read = read_prefix(2U); !read) {
        return std::unexpected(read.error());
    }
    if (filled < 2U || bytes[0] != '#' || bytes[1] != '!') {
        if (!unchanged()) {
            return std::unexpected(std::string{"harness directive source changed"});
        }
        return std::nullopt;
    }
    if (auto read = read_prefix(bytes.size()); !read) {
        return std::unexpected(read.error());
    }
    if (!unchanged()) {
        return std::unexpected(std::string{"harness directive source changed"});
    }
    const std::string_view remainder{bytes.data() + 2, filled - 2U};
    const auto newline = remainder.find('\n');
    const auto directive = remainder.substr(0, newline);
    if (directive.size() > 4094U || directive.find('\0') != std::string_view::npos) {
        return std::unexpected(
            std::string{"harness interpreter directive exceeds its bound or contains NUL"}
        );
    }
    const std::string first_line{directive};
    std::istringstream shebang{first_line};
    std::vector<std::string> fields;
    for (std::string field; shebang >> field;) {
        fields.push_back(std::move(field));
    }
    if (fields.empty() || fields.size() > 2U) {
        return std::unexpected(std::string{"unsupported harness interpreter directive"});
    }

    return fields;
}

auto derive_runtime_dependency_closure(
    const std::filesystem::path& source_entry,
    const std::filesystem::path& source,
    bool allow_dependency_commands
) -> result<runtime_dependency_closure> {
    auto directive = read_runtime_shebang(source);
    if (!directive) {
        return std::unexpected(directive.error());
    }
    if (!*directive) {
        return runtime_dependency_closure{
            .executable = source,
            .arguments = {},
            .read_only_paths = {source},
        };
    }
    const auto& fields = **directive;
    std::filesystem::path interpreter;
    std::error_code error;
    if (fields.front() == "/usr/bin/env") {
        if (fields.size() != 2U || fields[1].find('/') != std::string::npos) {
            return std::unexpected(std::string{"unsupported env-based harness interpreter"});
        }
        interpreter = std::filesystem::canonical(source_entry.parent_path() / fields[1], error);
        if (error) {
            return std::unexpected(
                "resolve adjacent harness interpreter " + fields[1] + ": " + error.message()
            );
        }
    } else {
        if (fields.size() != 1U || !std::filesystem::path{fields.front()}.is_absolute()) {
            return std::unexpected(std::string{"harness interpreter must be absolute"});
        }
        interpreter = std::filesystem::canonical(fields.front(), error);
        if (error) {
            return std::unexpected("resolve harness interpreter: " + error.message());
        }
    }
    const auto status = std::filesystem::status(interpreter, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return std::unexpected(std::string{"harness interpreter is not a regular file"});
    }

    std::vector<std::filesystem::path> roots{package_root_for(source)};
    if (const auto keg = homebrew_keg_for(interpreter)) {
        if (auto appended = append_homebrew_runtime_closure(*keg, roots, allow_dependency_commands);
            !appended) {
            return std::unexpected(appended.error());
        }
    } else if (fields.front() == "/usr/bin/env") {
        const auto installation_root = interpreter.parent_path().parent_path();
        if (installation_root == installation_root.root_path()) {
            return std::unexpected(
                std::string{"refusing root-wide interpreter dependency closure"}
            );
        }
        roots.push_back(installation_root);
    } else {
        roots.push_back(interpreter);
    }
    return runtime_dependency_closure{
        .executable = std::move(interpreter),
        .arguments = {source.string()},
        .read_only_paths = minimise_roots(std::move(roots)),
    };
}

auto path_ancestors_are_launch_trusted(const std::filesystem::path& path) -> bool {
    std::error_code error;
    auto current = std::filesystem::is_directory(path, error)
                       ? std::filesystem::canonical(path, error)
                       : std::filesystem::canonical(path, error).parent_path();
    if (error || current.empty()) {
        return false;
    }
    for (;;) {
        struct stat metadata{};
        if (::stat(current.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            (metadata.st_uid != 0 && metadata.st_uid != ::geteuid())) {
            return false;
        }
        const bool writable_by_other = (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0;
        const bool root_owned_sticky = metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0;
        if (writable_by_other && !root_owned_sticky) {
            return false;
        }
        if (current == current.root_path()) {
            return true;
        }
        current = current.parent_path();
    }
}

auto closure_launch_is_trusted(const runtime_dependency_closure& closure) -> bool {
    return path_ancestors_are_launch_trusted(closure.executable) &&
           std::ranges::all_of(closure.read_only_paths, path_ancestors_are_launch_trusted);
}

auto snapshot_payload_root(const std::filesystem::path& payload_root, std::size_t index)
    -> std::filesystem::path {
    return payload_root / ("root-" + std::to_string(index));
}

auto map_snapshot_path(
    const std::filesystem::path& source,
    std::span<const std::filesystem::path> closure_roots,
    const std::filesystem::path& payload_root
) -> result<std::filesystem::path> {
    for (std::size_t index = 0; index < closure_roots.size(); ++index) {
        const auto& closure_root = closure_roots[index];
        const auto mapped_root = snapshot_payload_root(payload_root, index);
        if (std::filesystem::is_regular_file(closure_root)) {
            if (source == closure_root) {
                return mapped_root / closure_root.filename();
            }
            continue;
        }
        if (path_within(source, closure_root)) {
            return mapped_root / source.lexically_relative(closure_root);
        }
    }
    return std::unexpected(std::string{"runtime path is outside its snapshot closure"});
}

auto snapshot_closure_digest(
    std::span<const std::filesystem::path> roots,
    std::uint64_t* logical_bytes,
    std::uint64_t* entry_count
) -> result<std::string> {
    if (roots.empty() || roots.size() > 64U) {
        return std::unexpected(std::string{"runtime snapshot has an invalid closure root count"});
    }
    std::string manifest{"glove.runtime-snapshot.v2", 25U};
    std::uint64_t total_bytes = 0;
    std::uint64_t total_entries = 0;
    for (const auto& root : roots) {
        std::uint64_t root_bytes = 0;
        std::uint64_t root_entries = 0;
        auto digest = snapshot_tree_digest(root, &root_bytes, &root_entries);
        if (!digest) {
            return std::unexpected(digest.error());
        }
        if (root_bytes > max_snapshot_bytes - total_bytes ||
            root_entries > max_snapshot_entries - total_entries) {
            return std::unexpected(
                std::string{"combined harness snapshot exceeds its safety limit"}
            );
        }
        total_bytes += root_bytes;
        total_entries += root_entries;
        manifest.push_back('\0');
        manifest.append(*digest);
    }
    const auto bytes = std::span{
        reinterpret_cast<const unsigned char*>(manifest.data()),
        manifest.size(),
    };
    auto digest = container::sha256_hex(bytes);
    if (!digest) {
        return std::unexpected(std::string{"hash combined harness snapshot manifest"});
    }
    if (logical_bytes != nullptr) {
        *logical_bytes = total_bytes;
    }
    if (entry_count != nullptr) {
        *entry_count = total_entries;
    }
    return *digest;
}

auto materialized_snapshot_digest(const std::filesystem::path& payload_root, std::size_t root_count)
    -> result<std::string> {
    std::vector<std::filesystem::path> roots;
    roots.reserve(root_count);
    for (std::size_t index = 0; index < root_count; ++index) {
        roots.push_back(snapshot_payload_root(payload_root, index));
    }
    return snapshot_closure_digest(roots);
}

auto plan_runtime_snapshot(
    const std::filesystem::path& protected_directory,
    const std::filesystem::path& source,
    const runtime_dependency_closure& closure
) -> result<planned_runtime_snapshot> {
    std::uint64_t logical_bytes = 0;
    std::uint64_t entries = 0;
    auto digest = snapshot_closure_digest(closure.read_only_paths, &logical_bytes, &entries);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    const auto snapshot_root = protected_directory / "snapshots" / *digest;
    const auto payload_root = snapshot_root / "payload";
    auto mapped_source = map_snapshot_path(source, closure.read_only_paths, payload_root);
    auto mapped_executable =
        map_snapshot_path(closure.executable, closure.read_only_paths, payload_root);
    if (!mapped_source || !mapped_executable) {
        return std::unexpected(!mapped_source ? mapped_source.error() : mapped_executable.error());
    }
    std::vector<std::string> mapped_arguments;
    mapped_arguments.reserve(closure.arguments.size());
    for (const auto& argument : closure.arguments) {
        const std::filesystem::path candidate{argument};
        if (!candidate.is_absolute()) {
            mapped_arguments.push_back(argument);
            continue;
        }
        auto mapped = map_snapshot_path(candidate, closure.read_only_paths, payload_root);
        if (!mapped) {
            return std::unexpected(mapped.error());
        }
        mapped_arguments.push_back(mapped->string());
    }
    return planned_runtime_snapshot{
        .digest = std::move(*digest),
        .logical_bytes = logical_bytes,
        .entries = entries,
        .snapshot_root = snapshot_root,
        .payload_root = payload_root,
        .mapped_source = std::move(*mapped_source),
        .source_roots = closure.read_only_paths,
        .closure = {
            .executable = std::move(*mapped_executable),
            .arguments = std::move(mapped_arguments),
            .read_only_paths = {payload_root},
        },
    };
}

auto protect_snapshot_tree(const std::filesystem::path& payload_root) -> result<void> {
    std::error_code error;
    std::vector<std::filesystem::path> entries;
    if (std::filesystem::is_directory(payload_root, error)) {
        for (std::filesystem::recursive_directory_iterator
                 iterator{payload_root, std::filesystem::directory_options::none, error},
             end;
             iterator != end;
             iterator.increment(error)) {
            if (error) {
                return std::unexpected("enumerate staged harness snapshot: " + error.message());
            }
            if (entries.size() >= 200'000U + 64U + 1U || iterator.depth() > 129 ||
                iterator->path().native().size() > 4096U) {
                return std::unexpected(std::string{"snapshot sealing enumeration exceeds bounds"});
            }
            entries.push_back(iterator->path());
        }
    }
    std::ranges::reverse(entries);
    entries.push_back(payload_root);
    // Inspect every entry before sealing any; never treat chmod as ACL revocation.
    // Created objects were already cleared through their exclusive descriptors.
    const auto inspect_and_seal = [](const std::filesystem::path& entry,
                                     bool seal) -> result<void> {
        struct stat named{};
        if (::lstat(entry.c_str(), &named) != 0) {
            return std::unexpected(system_error("inspect staged harness snapshot"));
        }
        if (S_ISLNK(named.st_mode)) {
            struct directory_guard {
                int fd;
                ~directory_guard() {
                    if (fd >= 0) {
                        (void)::close(fd);
                    }
                }
            } parent{::open(
                entry.parent_path().c_str(),
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            )};
            if (parent.fd < 0) {
                return std::unexpected(system_error("open symlink sealing parent"));
            }
            if (auto checked = glove::detail::check_descriptor_acl(
                    parent.fd, glove::detail::acl_scope::integrity
                );
                !checked) {
                return checked;
            }
            return glove::detail::check_symlink_acl_at(parent.fd, entry.filename().native(), named);
        }
        if (named.st_uid != ::geteuid() ||
            (!S_ISDIR(named.st_mode) && (!S_ISREG(named.st_mode) || named.st_nlink != 1)) ||
            (named.st_mode & (S_ISUID | S_ISGID | S_ISVTX | S_IRWXG | S_IRWXO)) != 0) {
            return std::unexpected(std::string{"unsafe staged snapshot entry before sealing"});
        }
        struct owned_fd {
            int value;
            explicit owned_fd(int fd) : value{fd} {}
            owned_fd(const owned_fd&) = delete;
            auto operator=(const owned_fd&) -> owned_fd& = delete;
            ~owned_fd() {
                if (value >= 0) {
                    (void)::close(value);
                }
            }
        } fd{::open(
            entry.c_str(),
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC |
                (S_ISDIR(named.st_mode) ? O_DIRECTORY : 0)
        )};
        struct stat opened{};
        if (fd.value < 0 || ::fstat(fd.value, &opened) != 0 || named.st_dev != opened.st_dev ||
            named.st_ino != opened.st_ino || named.st_uid != opened.st_uid ||
            named.st_mode != opened.st_mode || named.st_nlink != opened.st_nlink) {
            return std::unexpected(std::string{"snapshot sealing entry changed on open"});
        }
        if (auto acl =
                glove::detail::check_descriptor_acl(fd.value, glove::detail::acl_scope::integrity);
            !acl) {
            return acl;
        }
        const mode_t mode =
            S_ISDIR(opened.st_mode) || (opened.st_mode & S_IXUSR) != 0 ? 0500 : 0400;
        if (seal && ::fchmod(fd.value, mode) != 0) {
            return std::unexpected(system_error("seal pinned snapshot entry"));
        }
        struct stat after{};
        struct stat rebound{};
        if (::fstat(fd.value, &after) != 0 || ::lstat(entry.c_str(), &rebound) != 0 ||
            opened.st_dev != after.st_dev || opened.st_ino != after.st_ino ||
            opened.st_uid != after.st_uid || after.st_dev != rebound.st_dev ||
            after.st_ino != rebound.st_ino || after.st_uid != rebound.st_uid ||
            after.st_mode != rebound.st_mode || after.st_nlink != rebound.st_nlink ||
            (seal && (after.st_mode & 07777U) != mode)) {
            return std::unexpected(std::string{"snapshot sealing entry binding changed"});
        }
        return glove::detail::check_descriptor_acl(fd.value, glove::detail::acl_scope::integrity);
    };
    for (const auto& entry : entries) {
        if (auto checked = inspect_and_seal(entry, false); !checked) {
            return checked;
        }
    }
    for (const auto& entry : entries) {
        if (auto sealed = inspect_and_seal(entry, true); !sealed) {
            return sealed;
        }
    }
    return {};
}

auto materialize_runtime_snapshot(const planned_runtime_snapshot& plan) -> result<bool> {
    const auto snapshots = plan.snapshot_root.parent_path();
    if (auto prepared = ensure_protected_directory(snapshots.parent_path(), true); !prepared) {
        return std::unexpected(prepared.error());
    }
    if (auto prepared = ensure_protected_directory(snapshots, true); !prepared) {
        return std::unexpected(prepared.error());
    }
    std::error_code error;
    if (std::filesystem::exists(plan.snapshot_root, error)) {
        struct stat metadata{};
        if (::lstat(plan.snapshot_root.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            metadata.st_uid != ::geteuid() ||
            (static_cast<unsigned int>(metadata.st_mode) & 0777U) != 0500U) {
            return std::unexpected(
                std::string{"existing runtime snapshot root is not owner-protected"}
            );
        }
        if (auto acl_tree =
                validate_protected_snapshot_tree(plan.snapshot_root, plan.source_roots.size());
            !acl_tree) {
            return std::unexpected(acl_tree.error());
        }
        auto existing_digest =
            materialized_snapshot_digest(plan.payload_root, plan.source_roots.size());
        if (!existing_digest || *existing_digest != plan.digest) {
            return std::unexpected(
                std::string{"existing runtime snapshot does not match its content address"}
            );
        }
        return false;
    }
    if (error) {
        return std::unexpected("inspect runtime snapshot: " + error.message());
    }
    const auto temporary =
        snapshots / (".staging-" + plan.digest + "-" + std::to_string(::getpid()));
    if (std::filesystem::exists(temporary, error) || error) {
        return std::unexpected(std::string{"runtime snapshot staging path already exists"});
    }

    struct staging_handles {
        staging_handles() = default;
        staging_handles(const staging_handles&) = delete;
        auto operator=(const staging_handles&) -> staging_handles& = delete;

        ~staging_handles() {
            if (payload >= 0) {
                (void)::close(payload);
            }
            if (root >= 0) {
                (void)::close(root);
            }
            if (parent >= 0) {
                (void)::close(parent);
            }
        }

        int parent{-1};
        int root{-1};
        int payload{-1};
    } owned;

    owned.parent = ::open(snapshots.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat parent_metadata{};
    if (owned.parent < 0 || ::fstat(owned.parent, &parent_metadata) != 0 ||
        !S_ISDIR(parent_metadata.st_mode) || parent_metadata.st_uid != ::geteuid() ||
        (parent_metadata.st_mode & 07777U) != 0700U) {
        return std::unexpected(std::string{"runtime snapshot parent is not owner-protected"});
    }
    if (auto acl = glove::detail::check_descriptor_acl(
            owned.parent, glove::detail::acl_scope::owner_private
        );
        !acl) {
        return std::unexpected(acl.error());
    }
    const auto temporary_name = temporary.filename().string();
    if (::mkdirat(owned.parent, temporary_name.c_str(), 0700) != 0) {
        return std::unexpected(system_error("create runtime snapshot staging directory"));
    }
    owned.root = ::openat(
        owned.parent, temporary_name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    );
    struct stat created{};
    if (owned.root < 0 || ::fstat(owned.root, &created) != 0 || created.st_uid != ::geteuid() ||
        !S_ISDIR(created.st_mode) || (created.st_mode & 07777U) != 0700U) {
        return std::unexpected(
            std::string{"cannot pin new runtime staging directory; cleanup ownership unknown"}
        );
    }
    const auto temporary_payload = temporary / "payload";
    const auto fail_with_cleanup = [&](std::string failure) -> std::unexpected<std::string> {
        auto removed = remove_owned_staging_tree(owned.parent, temporary_name, owned.root);
        if (!removed) {
            failure += "; staging cleanup failed: " + removed.error();
        }
        return std::unexpected(std::move(failure));
    };
    struct stat root_named{};
    if (::fstatat(owned.parent, temporary_name.c_str(), &root_named, AT_SYMLINK_NOFOLLOW) != 0 ||
        root_named.st_dev != created.st_dev || root_named.st_ino != created.st_ino ||
        root_named.st_uid != created.st_uid || root_named.st_mode != created.st_mode) {
        return fail_with_cleanup("new snapshot staging root binding changed");
    }
    if (auto acl = glove::detail::clear_created_descriptor_acl(owned.root); !acl) {
        return fail_with_cleanup(acl.error());
    }
    if (::mkdirat(owned.root, "payload", 0700) != 0) {
        return fail_with_cleanup(system_error("create runtime snapshot payload"));
    }
    owned.payload = ::openat(
        owned.root, "payload", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
    );
    struct stat payload_created{};
    struct stat payload_named{};
    if (owned.payload < 0 || ::fstat(owned.payload, &payload_created) != 0 ||
        !S_ISDIR(payload_created.st_mode) || payload_created.st_uid != ::geteuid() ||
        (payload_created.st_mode & 07777U) != 0700U ||
        ::fstatat(owned.root, "payload", &payload_named, AT_SYMLINK_NOFOLLOW) != 0 ||
        payload_created.st_dev != payload_named.st_dev ||
        payload_created.st_ino != payload_named.st_ino ||
        payload_created.st_uid != payload_named.st_uid ||
        payload_created.st_mode != payload_named.st_mode) {
        return fail_with_cleanup("new snapshot payload binding is unsafe");
    }
    if (auto acl = glove::detail::clear_created_descriptor_acl(owned.payload); !acl) {
        return fail_with_cleanup(acl.error());
    }
    if (auto copied = copy_runtime_closure(
            plan.source_roots, temporary_payload, plan.logical_bytes, plan.entries
        );
        !copied) {
        return fail_with_cleanup("copy runtime snapshot: " + copied.error());
    }
    auto copied_digest = materialized_snapshot_digest(temporary_payload, plan.source_roots.size());
    if (!copied_digest || *copied_digest != plan.digest) {
        return fail_with_cleanup(
            copied_digest ? std::string{"runtime source changed while it was being snapshotted"}
                          : copied_digest.error()
        );
    }
    if (auto protected_tree = protect_snapshot_tree(temporary_payload); !protected_tree) {
        return fail_with_cleanup(protected_tree.error());
    }
    // Publish under an owner-only parent before sealing the final root. Some
    // platforms reject renaming a non-writable directory; the verified 0700
    // parent prevents another principal from observing this transition.
    if (::renameat(
            owned.parent,
            temporary_name.c_str(),
            owned.parent,
            plan.snapshot_root.filename().c_str()
        ) != 0) {
        const int rename_error = errno;
        auto removed = remove_owned_staging_tree(owned.parent, temporary_name, owned.root);
        if (!removed) {
            return std::unexpected(
                system_error("publish runtime snapshot", rename_error) +
                "; staging cleanup failed: " + removed.error()
            );
        }
        if (rename_error == EEXIST || rename_error == ENOTEMPTY) {
            if (auto acl_tree =
                    validate_protected_snapshot_tree(plan.snapshot_root, plan.source_roots.size());
                !acl_tree) {
                return std::unexpected(acl_tree.error());
            }
            auto existing_digest =
                materialized_snapshot_digest(plan.payload_root, plan.source_roots.size());
            if (existing_digest && *existing_digest == plan.digest) {
                return false;
            }
        }
        return std::unexpected(system_error("publish runtime snapshot", rename_error));
    }
    if (::fchmod(owned.root, 0500) != 0) {
        const int protection_error = errno;
        auto removed = remove_owned_staging_tree(
            owned.parent, plan.snapshot_root.filename().string(), owned.root
        );
        auto failure = system_error("protect runtime snapshot root", protection_error);
        if (!removed) {
            failure += "; published snapshot cleanup failed: " + removed.error();
        }
        return std::unexpected(std::move(failure));
    }
    return true;
}

} // namespace glove::host::snapshot
