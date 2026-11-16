#include "glove/container/profile.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kMaxInputBytes = 16U * 1024U;

auto split_fields(std::string_view input) -> std::vector<std::string> {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (start < input.size() && fields.size() < 16U) {
        const auto nl = input.find('\n', start);
        if (nl == std::string_view::npos) {
            fields.emplace_back(input.substr(start));
            break;
        }
        fields.emplace_back(input.substr(start, nl - start));
        start = nl + 1U;
    }
    return fields;
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size == 0 || size > kMaxInputBytes) {
        return 0;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view raw{reinterpret_cast<const char*>(data), size};
    const auto fields = split_fields(raw);
    glove::container::profile prof;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto& f = fields[i];
        const auto selector = static_cast<unsigned char>(data[i % size]) % 6U;
        switch (selector) {
        case 0:
            prof.filesystem.push_back({.path = f, .writable = (i % 2U == 0U)});
            break;
        case 1:
            prof.runtime_filesystem.push_back({.path = f, .writable = (i % 5U == 0U)});
            break;
        case 2:
            prof.environment.push_back(f);
            break;
        case 3:
            prof.home_dir = f;
            break;
        case 4:
            prof.work_dir = f;
            break;
        default:
            prof.reserved_entries.push_back({.parent = f, .name = "reserved"});
            break;
        }
    }
    if ((static_cast<unsigned char>(data[0]) & 1U) != 0U) {
        prof.proxy = glove::container::proxy_settings{.port = 8080, .url = "http://127.0.0.1:8080"};
    }
    if ((static_cast<unsigned char>(data[0]) & 2U) != 0U) {
        prof.bridge_endpoint = glove::container::bridge_endpoint_settings{.port = 9090};
    }

    auto validated = glove::container::validate(prof);
    if (validated) {
        // Core invariants that must always hold on any validated profile:
        // 1. Proxy and bridge_endpoint are mutually exclusive.
        if (validated->proxy && validated->bridge_endpoint) {
            __builtin_trap();
        }
        // 2. No filesystem or runtime grant is the filesystem root or contains NUL.
        for (const auto& rule : validated->filesystem) {
            if (rule.path.empty() || rule.path == "/" ||
                rule.path.find('\0') != std::string::npos) {
                __builtin_trap();
            }
        }
        for (const auto& rule : validated->runtime_filesystem) {
            if (rule.writable || rule.path.empty() || rule.path == "/" ||
                rule.path.find('\0') != std::string::npos) {
                __builtin_trap();
            }
        }
    }
    return 0;
}
