#include "glove/supervisor/sage_bundle_projection.hpp"

#include "glove/container/digest.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <limits>
#include <set>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace glove::supervisor {

namespace {

auto system_error(std::string_view operation) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{errno, std::generic_category()}.message();
}

auto append_string(std::vector<unsigned char>& output, std::string_view value)
    -> std::expected<void, std::string> {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(std::string{"Sage bundle projection field exceeds u32"});
    }
    const auto size = static_cast<std::uint32_t>(value.size());
    for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<unsigned char>((size >> shift) & 0xffU));
    }
    output.insert(output.end(), value.begin(), value.end());
    return {};
}

auto write_all(int descriptor, std::span<const unsigned char> bytes)
    -> std::expected<void, std::string> {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written <= 0) {
            return std::unexpected(system_error("write Sage bundle projection"));
        }
        offset += static_cast<std::size_t>(written);
    }
    return {};
}

} // namespace

auto sage_bundle_projection_digest(std::span<const resolved_library_projection> projections)
    -> std::expected<std::string, std::string> {
    std::vector<unsigned char> material;
    if (auto appended = append_string(material, "glove.sage-bundle-projection.v1"); !appended) {
        return std::unexpected(appended.error());
    }
    for (const auto& projection : projections) {
        for (const auto field : {
                 std::string_view{projection.projection_id},
                 std::string_view{projection.destination_alias},
                 projection.bundle.content_digest(),
                 sage_bundle_projection_schema,
             }) {
            if (auto appended = append_string(material, field); !appended) {
                return std::unexpected(appended.error());
            }
        }
    }
    return container::sha256_hex(std::span<const unsigned char>{material});
}

auto materialize_sage_bundle_projection(
    int directory_fd, std::span<const resolved_library_projection> projections
) -> std::expected<void, std::string> {
    if (directory_fd < 0) {
        return std::unexpected(std::string{"Sage bundle projection directory is invalid"});
    }
    std::set<std::string> unique_digests;
    std::uint64_t total_bytes = 0;
    for (const auto& projection : projections) {
        const std::string digest{projection.bundle.content_digest()};
        if (!unique_digests.insert(digest).second) {
            continue;
        }
        const auto size = projection.bundle.size_bytes();
        if (size > max_sage_bundle_projection_bytes - total_bytes) {
            return std::unexpected(
                std::string{"Sage bundle projection exceeds aggregate byte bound"}
            );
        }
        total_bytes += size;
    }
    std::set<std::string> materialized_digests;
    for (const auto& projection : projections) {
        const std::string digest{projection.bundle.content_digest()};
        if (!materialized_digests.insert(digest).second) {
            continue;
        }
        if (auto verified = projection.bundle.verify_identity(); !verified) {
            return std::unexpected(verified.error());
        }
        auto bytes = projection.bundle.read_bytes(max_library_bundle_bytes);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        auto buffered_digest = container::sha256_hex(std::span<const unsigned char>{*bytes});
        if (!buffered_digest || *buffered_digest != digest) {
            return std::unexpected(std::string{"Sage bundle projection snapshot digest changed"});
        }
        const std::string filename = digest + ".json";
        const int descriptor = ::openat(
            directory_fd,
            filename.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0400
        );
        if (descriptor < 0) {
            return std::unexpected(system_error("create Sage bundle projection"));
        }
        auto written = write_all(descriptor, *bytes);
        const bool synced = ::fsync(descriptor) == 0;
        const bool protected_file = ::fchmod(descriptor, 0444) == 0;
        const int close_result = ::close(descriptor);
        if (!written) {
            return std::unexpected(written.error());
        }
        if (!synced || !protected_file || close_result != 0) {
            return std::unexpected(system_error("seal Sage bundle projection"));
        }
        if (auto verified = projection.bundle.verify_identity(); !verified) {
            return std::unexpected(verified.error());
        }
    }
    if (::fchmod(directory_fd, 0555) != 0 || ::fsync(directory_fd) != 0) {
        return std::unexpected(system_error("seal Sage bundle projection directory"));
    }
    return {};
}

} // namespace glove::supervisor
