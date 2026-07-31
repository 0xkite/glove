#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace glove::container::detail {

class sha256_stream {
public:
    [[nodiscard]] auto update(std::span<const unsigned char> input)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto digest_hex() const -> std::expected<std::string, std::string>;

    [[nodiscard]] auto byte_count() const noexcept -> std::uint64_t { return total_bytes_; }

private:
    void transform() noexcept;
    [[nodiscard]] auto finish() noexcept -> std::array<unsigned char, 32>;

    std::array<std::uint32_t, 8> state_ = {
        0x6a09e667U,
        0xbb67ae85U,
        0x3c6ef372U,
        0xa54ff53aU,
        0x510e527fU,
        0x9b05688cU,
        0x1f83d9abU,
        0x5be0cd19U,
    };
    std::array<unsigned char, 64> block_{};
    std::size_t block_size_ = 0;
    std::uint64_t total_bytes_ = 0;
};

// Dependency-free SHA-256 used for versioned launch-profile commitments. It is
// an integrity primitive only; receipt authenticity is supplied by the
// supervisor audit HMAC.
[[nodiscard]] auto sha256_hex(std::span<const unsigned char> input)
    -> std::expected<std::string, std::string>;

// Hash a seek-independent regular-file view without changing its offset.
// `max_bytes` is a caller-owned denial-of-service bound.
[[nodiscard]] auto sha256_fd_hex(int descriptor, std::uint64_t max_bytes)
    -> std::expected<std::string, std::string>;

} // namespace glove::container::detail
