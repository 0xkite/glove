#include "glove/container/digest.hpp"
#include "glove/supervisor/library_bundle.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>
#include <utility>

namespace {

constexpr std::size_t maximum_bundle_bytes = 1024U * 1024U;

class unique_fd {
public:
    explicit unique_fd(int descriptor) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

class temporary_bundle_root {
public:
    temporary_bundle_root() {
        constexpr char directory_template[] = "/tmp/glove-library-bundle-fuzzer-XXXXXX";
        std::array<char, sizeof(directory_template)> directory_buffer{};
        std::copy_n(directory_template, directory_buffer.size(), directory_buffer.begin());
        const char* const created_directory = ::mkdtemp(directory_buffer.data());
        if (created_directory == nullptr) {
            std::abort();
        }
        root_ = created_directory;
    }

    temporary_bundle_root(const temporary_bundle_root&) = delete;
    auto operator=(const temporary_bundle_root&) -> temporary_bundle_root& = delete;

    ~temporary_bundle_root() {
        if (!current_path_.empty()) {
            (void)::unlink(current_path_.c_str());
        }
        if (!root_.empty()) {
            (void)::rmdir(root_.c_str());
        }
    }

    [[nodiscard]] auto
    overwrite(std::string_view digest, const std::uint8_t* data, std::size_t size) -> bool {
        if (!current_path_.empty() && ::unlink(current_path_.c_str()) != 0) {
            return false;
        }
        current_path_ = root_ + "/" + std::string{digest} + ".json";
        const unique_fd descriptor{::open(
            current_path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
        )};
        if (descriptor.get() < 0) {
            return false;
        }
        std::size_t written = 0;
        while (written < size) {
            const auto result = ::write(descriptor.get(), data + written, size - written);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                return false;
            }
            written += static_cast<std::size_t>(result);
        }
        return true;
    }

    [[nodiscard]] auto path() const -> const std::string& { return root_; }

private:
    std::string root_;
    std::string current_path_;
};

auto bundle_root() -> temporary_bundle_root& {
    static temporary_bundle_root root;
    return root;
}

auto bundle_store() -> glove::supervisor::library_bundle_store& {
    static glove::supervisor::library_bundle_store store = [] {
        auto opened = glove::supervisor::library_bundle_store::open(bundle_root().path());
        if (!opened) {
            std::abort();
        }
        return std::move(*opened);
    }();
    return store;
}

auto digest_for(const std::uint8_t* data, std::size_t size) -> std::string {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::span bytes{reinterpret_cast<const unsigned char*>(data), size};
    auto digest = glove::container::sha256_hex(bytes);
    if (!digest) {
        std::abort();
    }
    return std::move(*digest);
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > maximum_bundle_bytes) {
        return 0;
    }

    const std::string digest = digest_for(data, size);
    auto& root = bundle_root();
    if (!root.overwrite(digest, data, size)) {
        std::abort();
    }

    // Bundles remain opaque until prompt-library expansion exists. Exercise
    // the production descriptor, metadata, digest, and identity checks on
    // arbitrary staged content rather than inventing an unpublished format.
    auto resolved = bundle_store().resolve(digest);
    if (size == 0U) {
        if (resolved) {
            std::abort();
        }
    } else if (!resolved || !resolved->verify_identity()) {
        std::abort();
    }
    return 0;
}
