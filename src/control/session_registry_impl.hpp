#pragma once

#include "glove/control/session_registry.hpp"
#include "glove/control/session_registry_wire.hpp"

#include <glaze/glaze.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

namespace glove::control {

// On-disk registry constants and internal state shared by the registry store
// and its recovery/replay state machine. Internal-only: include from
// session_registry.cpp / session_registry_recovery.cpp.

constexpr std::array<unsigned char, 8> registry_magic = {'G', 'L', 'V', 'S', 'E', 'S', '0', '5'};
constexpr std::size_t digest_hex_bytes = 64U;
constexpr std::uint64_t min_registry_bytes = 1'024U;
constexpr std::size_t max_records = 10'000U;
constexpr std::size_t max_identifier_bytes = 128U;
constexpr std::uint64_t max_start_authorization_ttl_ms = 120'000U;
constexpr glz::opts partial_read_options{.error_on_unknown_keys = false};

class unique_fd {
public:
    explicit unique_fd(int descriptor = -1) noexcept : descriptor_{descriptor} {}

    unique_fd(const unique_fd&) = delete;
    auto operator=(const unique_fd&) -> unique_fd& = delete;

    unique_fd(unique_fd&& other) noexcept : descriptor_{std::exchange(other.descriptor_, -1)} {}

    auto operator=(unique_fd&& other) noexcept -> unique_fd& {
        if (this != &other) {
            if (descriptor_ >= 0) {
                (void)::close(descriptor_);
            }
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }

    ~unique_fd() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] auto get() const noexcept -> int { return descriptor_; }

private:
    int descriptor_ = -1;
};

struct opened_registry {
    unique_fd parent;
    unique_fd file;
    std::string name;
    bool created = false;
};

struct registry_identity {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    auto operator==(const registry_identity&) const -> bool = default;
};

inline auto failure(session_registry_error_code code, std::string message) -> session_registry_error {
    return {.code = code, .message = std::move(message)};
}

inline auto storage_failure(std::string message) -> session_registry_error {
    return failure(session_registry_error_code::storage, std::move(message));
}

inline auto system_error(std::string_view operation, int error_number = errno) -> std::string {
    return std::string{operation} + ": " +
           std::error_code{error_number, std::generic_category()}.message();
}

struct session_registry::implementation {
    opened_registry opened;
    std::shared_ptr<const supervisor::session_plan_validator> validator;
    std::shared_ptr<const supervisor::library_bundle_store> library_bundles;
    std::uint64_t max_bytes = 0;
    std::uint64_t durable_bytes = registry_magic.size();
    registry_identity identity;
    bool poisoned = false;
    std::vector<wire::persisted_session> records;
    std::unordered_map<std::string, std::size_t> sessions;
    std::unordered_map<std::string, std::size_t> requests;
    mutable std::mutex mutex;
};

} // namespace glove::control
