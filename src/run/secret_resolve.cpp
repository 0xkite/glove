#include "secret_resolve.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#    include <CoreFoundation/CoreFoundation.h>
#    include <Security/Security.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <ranges>
#include <system_error>
#include <utility>

namespace glove::run::detail {
namespace {

using result = std::expected<std::string, std::string>;

auto system_message(int error_number) -> std::string {
    return std::error_code{error_number, std::generic_category()}.message();
}

// One trailing newline (LF or CRLF) is a file convention, not secret text.
auto without_newline(std::string value) -> std::string {
    if (value.ends_with('\n')) {
        value.pop_back();
        if (value.ends_with('\r')) {
            value.pop_back();
        }
    }
    return value;
}

auto normal(const std::filesystem::path& path) -> std::filesystem::path {
    std::error_code ec;
    auto resolved = std::filesystem::weakly_canonical(path, ec);
    auto out = (ec ? path : resolved).lexically_normal();
    while (!out.has_filename() && out != out.root_path()) {
        out = out.parent_path();
    }
    return out;
}

auto inside(const std::filesystem::path& inner, const std::filesystem::path& outer) -> bool {
    const auto [end_outer, end_inner] = std::ranges::mismatch(outer, inner);
    static_cast<void>(end_inner);
    return end_outer == outer.end();
}

auto from_env(const secret_reference& reference) -> result {
    const char* value = std::getenv(reference.locator.c_str()); // NOLINT(concurrency-mt-unsafe)
    if (value == nullptr || *value == '\0') {
        return std::unexpected("secret env://" + reference.locator + " is unset or empty");
    }
    return std::string{value};
}

auto from_file(
    const secret_reference& reference,
    const std::filesystem::path& home,
    std::span<const std::string> exposed
) -> result {
    const auto& locator = reference.locator;
    std::filesystem::path path{locator};
    if (locator.starts_with("~/")) {
        if (!home.is_absolute() || home == home.root_path()) {
            return std::unexpected(
                "secret " + format_secret_reference(reference) + ": home directory is unknown"
            );
        }
        path = home / locator.substr(2);
    }
    const auto resolved = normal(path);
    for (const auto& grant : exposed) {
        const auto root = normal(std::filesystem::path{grant});
        if (inside(resolved, root) || inside(normal(path.lexically_normal()), root)) {
            return std::unexpected(
                "secret " + format_secret_reference(reference) +
                " is inside a path the sandbox can reach ('" + grant + "')"
            );
        }
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(
            "secret " + format_secret_reference(reference) + ": " + system_message(errno)
        );
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
    if (::fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != ::geteuid() || metadata.st_nlink != 1 ||
        (metadata.st_mode & 0077U) != 0 || metadata.st_size <= 0 ||
        std::cmp_greater(metadata.st_size, max_secret_bytes)) {
        return std::unexpected(
            "secret " + format_secret_reference(reference) +
            " must be a regular single-link file you own, with no group or other "
            "access (chmod 600), of at most 16 KiB"
        );
    }
    std::string value(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t consumed = 0;
    while (consumed < value.size()) {
        const auto got = ::read(fd, value.data() + consumed, value.size() - consumed);
        if (got < 0 && errno == EINTR) {
            continue;
        }
        if (got <= 0) {
            return std::unexpected(
                "secret " + format_secret_reference(reference) + " changed while reading"
            );
        }
        consumed += static_cast<std::size_t>(got);
    }
    return without_newline(std::move(value));
}

#if defined(__APPLE__)
template<typename T> struct cf_owner {
    T value = nullptr;
    cf_owner() = default;

    explicit cf_owner(T held) : value{held} {}

    cf_owner(const cf_owner&) = delete;
    auto operator=(const cf_owner&) -> cf_owner& = delete;
    cf_owner(cf_owner&&) = delete;
    auto operator=(cf_owner&&) -> cf_owner& = delete;

    ~cf_owner() {
        if (value != nullptr) {
            CFRelease(value);
        }
    }
};

auto cf_string(const std::string& text) -> cf_owner<CFStringRef> {
    return cf_owner<CFStringRef>{
        CFStringCreateWithBytes(
            kCFAllocatorDefault,
            reinterpret_cast<const UInt8*>(text.data()),
            static_cast<CFIndex>(text.size()),
            kCFStringEncodingUTF8,
            false
        ),
    };
}

auto from_keychain(const secret_reference& reference) -> result {
    const auto name = format_secret_reference(reference);
    const auto service = cf_string(reference.locator);
    const auto account = cf_string(reference.account);
    const cf_owner<CFMutableDictionaryRef> query{CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    )};
    if (service.value == nullptr || account.value == nullptr || query.value == nullptr) {
        return std::unexpected("secret " + name + ": cannot build the keychain query");
    }
    CFDictionarySetValue(query.value, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query.value, kSecAttrService, service.value);
    CFDictionarySetValue(query.value, kSecAttrAccount, account.value);
    CFDictionarySetValue(query.value, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query.value, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef found = nullptr;
    const OSStatus status = SecItemCopyMatching(query.value, &found);
    const cf_owner<CFTypeRef> data{found};
    if (status == errSecItemNotFound) {
        return std::unexpected("secret " + name + ": no such keychain item");
    }
    if (status != errSecSuccess || data.value == nullptr ||
        CFGetTypeID(data.value) != CFDataGetTypeID()) {
        return std::unexpected(
            "secret " + name + ": keychain lookup failed (OSStatus " + std::to_string(status) + ")"
        );
    }
    const auto* bytes = static_cast<CFDataRef>(data.value);
    const auto length = CFDataGetLength(bytes);
    if (length <= 0 || std::cmp_greater(length, max_secret_bytes)) {
        return std::unexpected("secret " + name + ": keychain item is empty or too large");
    }
    std::string value(
        reinterpret_cast<const char*>(CFDataGetBytePtr(bytes)), static_cast<std::size_t>(length)
    );
    return without_newline(std::move(value));
}
#else
auto from_keychain(const secret_reference& reference) -> result {
    return std::unexpected(
        "secret " + format_secret_reference(reference) + ": keychain:// is available on macOS only"
    );
}
#endif

} // namespace

auto valid_secret_value(std::string_view value) -> bool {
    return !value.empty() && value.size() <= max_secret_bytes &&
           std::ranges::all_of(value, [](char ch) {
               const auto byte = static_cast<unsigned char>(ch);
               return byte > 0x20U && byte != 0x7FU;
           });
}

auto resolve_secret(
    const secret_reference& reference,
    const std::filesystem::path& home,
    std::span<const std::string> exposed
) -> std::expected<std::string, std::string> {
    result value;
    switch (reference.source) {
    case secret_source::env:
        value = from_env(reference);
        break;
    case secret_source::file:
        value = from_file(reference, home, exposed);
        break;
    case secret_source::keychain:
        value = from_keychain(reference);
        break;
    }
    if (value && !valid_secret_value(*value)) {
        return std::unexpected(
            "secret " + format_secret_reference(reference) +
            " must be one token without spaces or control characters"
        );
    }
    return value;
}

} // namespace glove::run::detail
