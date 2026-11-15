#include "pi_private_state.hpp"

#include "native_harness_adapter.hpp"

#include <array>
#include <utility>

namespace glove::run::detail {

pi_private_state::pi_private_state(native_private_state state) noexcept
    : state_{std::move(state)} {}

pi_private_state::pi_private_state(pi_private_state&&) noexcept = default;
auto pi_private_state::operator=(pi_private_state&&) noexcept -> pi_private_state& = default;
pi_private_state::~pi_private_state() = default;

auto pi_private_state::create(
    const std::filesystem::path& parent,
    const pi_guest_config& config,
    pi_creation_rollback_barrier rollback_barrier
) -> std::expected<pi_private_state, std::string> {
    constexpr std::size_t budget = 32U * 1024U;
    if (config.models_json.size() > budget - 2 ||
        config.settings_json.size() > budget - 2 - config.models_json.size()) {
        return std::unexpected("Pi generated configuration exceeds 32 KiB logical budget");
    }
    const std::array<native_configuration_file, 3> files{
        {{.name = "models.json", .bytes = config.models_json},
         {.name = "settings.json", .bytes = config.settings_json},
         {.name = "auth.json", .bytes = "{}"}}
    };
    auto created = native_private_state::create(
        parent,
        files,
        {.context = rollback_barrier.context, .before_cleanup = rollback_barrier.before_cleanup}
    );
    if (!created) {
        return std::unexpected(created.error());
    }
    return pi_private_state{std::move(*created)};
}

auto pi_private_state::recover(const std::filesystem::path& parent)
    -> std::expected<std::size_t, std::string> {
    return native_private_state::recover(parent);
}

auto pi_private_state::root() const -> const std::filesystem::path& {
    return state_.root();
}

auto pi_private_state::home() const -> const std::filesystem::path& {
    return state_.home();
}

auto pi_private_state::tmp() const -> const std::filesystem::path& {
    return state_.tmp();
}

auto pi_private_state::agent() const -> const std::filesystem::path& {
    return state_.agent();
}

auto pi_private_state::sessions() const -> const std::filesystem::path& {
    return state_.sessions();
}

auto pi_private_state::models() const -> const std::filesystem::path& {
    return state_.configuration_paths()[0];
}

auto pi_private_state::settings() const -> const std::filesystem::path& {
    return state_.configuration_paths()[1];
}

auto pi_private_state::auth() const -> const std::filesystem::path& {
    return state_.configuration_paths()[2];
}

auto pi_private_state::mark_launching() -> std::expected<void, std::string> {
    return state_.mark_launching();
}

auto pi_private_state::mark_quiescent() -> std::expected<void, std::string> {
    return state_.mark_quiescent();
}

auto pi_private_state::cleanup() -> std::expected<void, std::string> {
    return state_.cleanup();
}

} // namespace glove::run::detail
