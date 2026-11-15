#include "native_harness_adapter.hpp"
#include "native_private_state.hpp"

#include <sys/random.h>
#include <unistd.h>

#include <array>

namespace glove::run::detail {

auto native_private_run_plan::root() const -> std::filesystem::path {
    return parent / name;
}

auto native_private_run_plan::paths() const -> native_private_paths {
    const auto owned_root = root();
    return {
        .home = owned_root / "home",
        .agent = owned_root / "agent",
        .sessions = owned_root / "sessions"
    };
}

auto prepare_native_private_run(const std::filesystem::path& parent)
    -> std::expected<native_private_run_plan, std::string> {
    const auto& value = parent.native();
    if (!parent.is_absolute() || parent == parent.root_path() ||
        value != parent.lexically_normal().native() || value.size() > 4096 ||
        value.find('\0') != std::string::npos || value.find("//") != std::string::npos ||
        value.back() == '/') {
        return std::unexpected("invalid native private parent path");
    }
    std::array<unsigned char, 24> random{};
    if (::getentropy(random.data(), random.size()) != 0) {
        return std::unexpected("cannot obtain native private run entropy");
    }
    native_private_run_plan plan{.parent = parent, .name = "run-"};
    constexpr std::string_view hex = "0123456789abcdef";
    for (const auto byte : random) {
        plan.name += hex[byte >> 4U];
        plan.name += hex[byte & 15U];
    }
    const auto paths = plan.paths();
    for (const auto* path : {&paths.home, &paths.agent, &paths.sessions}) {
        if (path->native().size() > 4096) {
            return std::unexpected("native private path exceeds bounds");
        }
    }
    return plan;
}

} // namespace glove::run::detail
