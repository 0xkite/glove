#include "glove/run/pi_launch.hpp"

#include "../adapters/pi/native_harness.hpp"
#include "native_launch.hpp"
#include "pi_catalog.hpp"
#include "pi_launch_internal.hpp"
#include "pi_machine_authorities.hpp"
#include "pi_native_policy.hpp"
#include "pi_runtime_internal.hpp"

#include <optional>
#include <utility>

namespace glove::run {
namespace fs = std::filesystem;
template<typename T> using result = std::expected<T, std::string>;

namespace detail {
namespace {

struct pi_host_authority {
    std::vector<fs::path> exclusions;
    pi_runtime_selection record;
    pi_launch_selection selected;
};

auto read_record(const fs::path& path, std::span<const fs::path> exclusions)
    -> result<pi_runtime_selection> {
    auto record = load_pi_runtime_with_exclusions(path, exclusions);
    if (!record) {
        return std::unexpected(
            "Pi runtime selection unavailable; run 'glove pi setup': " + record.error()
        );
    }
    if (!*record) {
        return std::unexpected("Pi runtime is not configured; run 'glove pi setup'");
    }
    return std::move(**record);
}

auto native_binding_for(const pi_runtime_selection& record, const pi_launch_selection& selected)
    -> native_launch_binding {
    return {
        .runtime = record.runtime,
        .provider = selected.model.provider == pi_provider::openai
                        ? net::endpoint_provider::openai
                        : net::endpoint_provider::anthropic,
        .model = selected.model.model,
        .arguments = selected.arguments
    };
}

auto assets_for(
    const pi_runtime_selection& record,
    const pi_launch_selection& selected,
    std::span<const fs::path> exclusions
) -> result<native_launch_assets> {
    auto catalog = load_pi_builtin_catalog(record, selected.model.provider, exclusions);
    if (!catalog) {
        return std::unexpected(catalog.error());
    }
    auto libraries = pi_library_environment_with_exclusions(record, exclusions);
    if (!libraries) {
        return std::unexpected(libraries.error());
    }
    return native_launch_assets{
        .catalog_json = std::move(*catalog), .library_environment = std::move(*libraries)
    };
}

} // namespace

auto launch_pi_with_adapter(
    const pi_launch_request& request,
    const pi_launch_context& context,
    const native_harness_adapter& adapter,
    std::stop_token stop
) -> result<int> {
    // These callbacks are trusted host policy. The common core admits stdio,
    // directories/backend and startup policy before allowing any descriptor opens.
    const auto record_path = context.directories.config / "pi/selection.json";
    std::optional<pi_host_authority> authority;
    native_launch_context native{
        .directories = context.directories,
        .protected_auth_roots = context.protected_auth_roots,
        .workspace = request.workspace,
        .runs = context.directories.runtime / "pi/runs",
        .policy = pi_native_startup_policy(),
        .display_name = "Pi",
        .backend = native_launch_backend::macos,
        .admit_runtime = {},
        .admit_assets = {},
        .revalidate = {},
        .credential = {},
        .start_endpoint = context.start_endpoint,
        .execute_owned = context.execute_owned,
        .audit = context.audit,
        .conversation_id = {},
        .resume = false,
        .materialize = {},
        .on_launching = {},
        .finalize = {}
    };
    native.admit_runtime = [&]() -> result<native_launch_binding> {
        auto exclusions = pi_source_authorities(context.directories, context.protected_auth_roots);
        if (!exclusions) {
            return std::unexpected(exclusions.error());
        }
        auto record = read_record(record_path, *exclusions);
        if (!record) {
            return std::unexpected(record.error());
        }
        auto selected = select_pi_launch(request.selection, record->model);
        if (!selected) {
            return std::unexpected(selected.error());
        }
        authority.emplace(
            pi_host_authority{
                .exclusions = std::move(*exclusions),
                .record = std::move(*record),
                .selected = std::move(*selected)
            }
        );
        return native_binding_for(authority->record, authority->selected);
    };
    native.admit_assets = [&](const native_launch_binding&) -> result<native_launch_assets> {
        if (!authority) {
            return std::unexpected("Pi host admission was not established");
        }
        return assets_for(authority->record, authority->selected, authority->exclusions);
    };
    native.revalidate = [&]() -> result<native_launch_authority> {
        if (!authority) {
            return std::unexpected("Pi host admission was not established");
        }
        auto current = read_record(record_path, authority->exclusions);
        if (!current || current->model != authority->record.model ||
            !same_native_runtime_binding(current->runtime, authority->record.runtime)) {
            return std::unexpected("Pi runtime selection changed before launch");
        }
        auto assets = assets_for(*current, authority->selected, authority->exclusions);
        if (!assets) {
            return std::unexpected("Pi catalog or runtime libraries changed before launch");
        }
        return native_launch_authority{
            .binding = native_binding_for(*current, authority->selected),
            .assets = std::move(*assets)
        };
    };
    if (context.credential) {
        native.credential = [&](net::endpoint_provider provider) -> result<std::string> {
            switch (provider) {
            case net::endpoint_provider::openai:
                return context.credential(pi_provider::openai);
            case net::endpoint_provider::anthropic:
                return context.credential(pi_provider::anthropic);
            default:
                return std::unexpected("unsupported Pi host credential provider");
            }
        };
    }
    return launch_native_with_context(native, adapter, stop);
}

auto launch_pi_with_context(
    const pi_launch_request& request, const pi_launch_context& context, std::stop_token stop
) -> result<int> {
    const adapters::pi_harness_adapter adapter;
    return launch_pi_with_adapter(request, context, adapter, stop);
}

} // namespace detail

auto launch_pi(const pi_launch_request& request, std::stop_token stop) -> result<int> {
#if !defined(__APPLE__)
    (void)request;
    (void)stop;
    return std::unexpected("glove pi requires the native macOS backend");
#else
    if (auto stdio = detail::admit_native_operator_stdio(); !stdio) {
        return std::unexpected(stdio.error());
    }
    const auto environment = host::current_environment();
    auto directories = host::resolve_directories(environment);
    if (!directories) {
        return std::unexpected(directories.error());
    }
    detail::pi_launch_context context{
        .directories = std::move(*directories),
        .protected_auth_roots = {},
        .credential = {},
        .start_endpoint = {},
        .execute_owned = {},
        .audit = {}
    };
    if (environment.home && !environment.home->empty()) {
        const fs::path home{*environment.home};
        context.protected_auth_roots = {
            home / ".pi",
            home / ".ssh",
            home / ".aws",
            home / ".config",
            home / ".netrc",
            home / ".npmrc"
        };
    }
    auto roots = detail::load_pi_machine_authorities(context.directories);
    if (!roots) {
        return std::unexpected(roots.error());
    }
    context.protected_auth_roots.insert(
        context.protected_auth_roots.end(), roots->begin(), roots->end()
    );
    return detail::launch_pi_with_context(request, context, stop);
#endif
}

} // namespace glove::run
