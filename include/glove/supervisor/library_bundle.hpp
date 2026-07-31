#pragma once

#include "glove/supervisor/session_plan.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace glove::supervisor {

inline constexpr std::uint64_t max_library_bundle_bytes = std::uint64_t{16} * 1024U * 1024U;

struct library_bundle_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint32_t mode = 0;

    auto operator==(const library_bundle_identity&) const -> bool = default;
};

// Identity-pinned, digest-verified view of one Sage-staged canonical bundle.
// The caller receives only an owned descriptor; the host path never becomes
// plan or remote authority.
class resolved_library_bundle final {
public:
    resolved_library_bundle(const resolved_library_bundle&) = delete;
    auto operator=(const resolved_library_bundle&) -> resolved_library_bundle& = delete;
    resolved_library_bundle(resolved_library_bundle&& other) noexcept;
    auto operator=(resolved_library_bundle&&) -> resolved_library_bundle& = delete;
    ~resolved_library_bundle();

    [[nodiscard]] auto descriptor_fd() const noexcept -> int { return descriptor_; }

    [[nodiscard]] auto content_digest() const noexcept -> std::string_view { return digest_; }

    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t { return size_bytes_; }

    [[nodiscard]] auto identity() const noexcept -> library_bundle_identity {
        return {
            .device = device_,
            .inode = inode_,
            .mode = static_cast<std::uint32_t>(mode_),
        };
    }

    // Repeat identity and content verification immediately before a mount or
    // copy. A replaced, relinked, chmodded, resized, or rewritten object fails.
    [[nodiscard]] auto verify_identity() const -> std::expected<void, std::string>;

    [[nodiscard]] auto read_bytes(std::uint64_t max_bytes) const
        -> std::expected<std::vector<unsigned char>, std::string>;

private:
    friend class library_bundle_store;

    resolved_library_bundle(
        int descriptor,
        std::string digest,
        std::uint64_t device,
        std::uint64_t inode,
        std::uint64_t size_bytes,
        std::uint64_t mode,
        std::uint64_t owner
    ) noexcept;

    int descriptor_ = -1;
    std::string digest_;
    std::uint64_t device_ = 0;
    std::uint64_t inode_ = 0;
    std::uint64_t size_bytes_ = 0;
    std::uint64_t mode_ = 0;
    std::uint64_t owner_ = 0;
};

// Exact bundle descriptor plus its protected, derived sandbox target. The
// target filename is always the content digest and never an untrusted manifest
// key or projection identifier.
struct resolved_library_projection {
    std::string projection_id;
    std::string destination_alias;
    std::string target_path;
    resolved_library_bundle bundle;
};

// Protected local lookup root for Sage's content-addressed bundle objects.
// The root must already exist as an absolute owner-only directory. It is
// descriptor-pinned and its pathname identity is rechecked around each lookup.
class library_bundle_store final {
public:
    library_bundle_store(const library_bundle_store&) = delete;
    auto operator=(const library_bundle_store&) -> library_bundle_store& = delete;
    library_bundle_store(library_bundle_store&& other) noexcept;
    auto operator=(library_bundle_store&&) -> library_bundle_store& = delete;
    ~library_bundle_store();

    [[nodiscard]] static auto open(const std::filesystem::path& root)
        -> std::expected<library_bundle_store, std::string>;

    [[nodiscard]] auto resolve(std::string_view content_digest) const
        -> std::expected<resolved_library_bundle, std::string>;

    // Resolve the complete projection set atomically. Partial failure destroys
    // every descriptor already opened, and duplicate derived targets fail.
    [[nodiscard]] auto
    resolve_projections(const std::vector<resolved_library_projection_target>& projections) const
        -> std::expected<std::vector<resolved_library_projection>, std::string>;

private:
    library_bundle_store(
        std::filesystem::path root,
        int descriptor,
        std::uint64_t device,
        std::uint64_t inode,
        std::uint64_t owner
    ) noexcept;

    [[nodiscard]] auto verify_root_identity() const -> std::expected<void, std::string>;

    std::filesystem::path root_;
    int descriptor_ = -1;
    std::uint64_t device_ = 0;
    std::uint64_t inode_ = 0;
    std::uint64_t owner_ = 0;
};

} // namespace glove::supervisor
