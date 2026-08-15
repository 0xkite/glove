#include "glove/supervisor/change_manifest.hpp"

#include "receipt_audit_wire.hpp"
#include "receipt_handlers.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::control::receipt_handlers {

using wire::path_exposure_projection;
using wire::rpc_params;

namespace {

constexpr glz::opts strict_read_options{.error_on_unknown_keys = true};

template<typename Value>
auto encode_json(const Value& value) -> std::expected<std::string, std::string> {
    auto encoded = glz::write_json(value);
    if (!encoded) {
        return std::unexpected(
            std::string{"control response encode: "} +
            glz::format_error(encoded.error(), std::string{})
        );
    }
    return std::move(*encoded);
}

template<typename Value>
auto decode_strict(std::string_view input) -> std::expected<Value, std::string> {
    Value value{};
    if (const auto error = glz::read<strict_read_options>(value, input); error) {
        return std::unexpected(glz::format_error(error, input));
    }
    return value;
}

auto parse_path_access(std::string_view value)
    -> std::expected<supervisor::path_access, std::string> {
    if (value == "read") {
        return supervisor::path_access::read;
    }
    if (value == "ephemeral_write") {
        return supervisor::path_access::ephemeral_write;
    }
    if (value == "retained_write") {
        return supervisor::path_access::retained_write;
    }
    return std::unexpected(std::string{"invalid path exposure access"});
}

auto parse_path_materialization(std::string_view value)
    -> std::expected<supervisor::path_materialization, std::string> {
    if (value == "bind") {
        return supervisor::path_materialization::bind;
    }
    if (value == "git_worktree") {
        return supervisor::path_materialization::git_worktree;
    }
    if (value == "copy") {
        return supervisor::path_materialization::copy;
    }
    return std::unexpected(std::string{"invalid path exposure materialization"});
}

auto parse_path_cleanup(std::string_view value)
    -> std::expected<supervisor::path_cleanup_policy, std::string> {
    if (value == "retain") {
        return supervisor::path_cleanup_policy::retain;
    }
    if (value == "remove") {
        return supervisor::path_cleanup_policy::remove;
    }
    return std::unexpected(std::string{"invalid path exposure cleanup policy"});
}

auto path_access_name(supervisor::path_access value) -> std::string_view {
    switch (value) {
    case supervisor::path_access::read:
        return "read";
    case supervisor::path_access::ephemeral_write:
        return "ephemeral_write";
    case supervisor::path_access::retained_write:
        return "retained_write";
    case supervisor::path_access::direct_write:
        return "direct_write";
    }
    return {};
}

auto path_materialization_name(supervisor::path_materialization value) -> std::string_view {
    switch (value) {
    case supervisor::path_materialization::bind:
        return "bind";
    case supervisor::path_materialization::snapshot:
        return "snapshot";
    case supervisor::path_materialization::git_worktree:
        return "git_worktree";
    case supervisor::path_materialization::copy:
        return "copy";
    }
    return {};
}

auto path_cleanup_name(supervisor::path_cleanup_policy value) -> std::string_view {
    switch (value) {
    case supervisor::path_cleanup_policy::retain:
        return "retain";
    case supervisor::path_cleanup_policy::remove:
        return "remove";
    }
    return {};
}

auto path_exposure_state_name(supervisor::path_exposure_state value) -> std::string_view {
    switch (value) {
    case supervisor::path_exposure_state::active:
        return "active";
    case supervisor::path_exposure_state::revoked:
        return "revoked";
    case supervisor::path_exposure_state::expired:
        return "expired";
    }
    return {};
}

auto project_path_exposure(const supervisor::path_exposure_projection& exposure)
    -> path_exposure_projection {
    std::vector<wire::path_exposure_mode> modes;
    modes.reserve(exposure.allowed_modes.size());
    for (const auto& mode : exposure.allowed_modes) {
        modes.push_back({
            .access = std::string{path_access_name(mode.access)},
            .materialization = std::string{path_materialization_name(mode.materialization)},
            .max_bytes = mode.max_bytes,
            .cleanup_policy = std::string{path_cleanup_name(mode.cleanup_policy)},
        });
    }
    return {
        .schema_version = exposure.schema_version,
        .exposure_id = exposure.exposure_id,
        .generation = exposure.generation,
        .scope_digest = exposure.scope_digest,
        .display_label = exposure.display_label,
        .allowed_modes = std::move(modes),
        .expires_at_ms = exposure.expires_at_ms,
        .allowed_runtime_template_ids = exposure.allowed_runtime_template_ids,
        .state = std::string{path_exposure_state_name(exposure.state)},
    };
}

} // namespace

using wire::create_path_exposure_request;
using wire::path_exposure_list_result;
using wire::path_exposure_result;
using wire::retained_change_entry;
using wire::retained_change_inspect_request;
using wire::retained_change_inspect_result;
using wire::revoke_path_exposure_request;

auto handle_create_path_exposure(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.path_exposures) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    if (!valid_identifier(idempotency_key)) {
        return error_response(
            request_id, "invalid_request", "path exposure creation requires idempotency"
        );
    }
    auto payload = decode_strict<create_path_exposure_request>(params.payload.str);
    if (!payload) {
        return error_response(request_id, "invalid_request", "invalid path exposure request");
    }
    std::vector<supervisor::path_exposure_mode> modes;
    modes.reserve(payload->allowed_modes.size());
    for (const auto& mode : payload->allowed_modes) {
        auto access = parse_path_access(mode.access);
        auto materialization = parse_path_materialization(mode.materialization);
        auto cleanup = parse_path_cleanup(mode.cleanup_policy);
        if (!access || !materialization || !cleanup) {
            return error_response(request_id, "invalid_request", "invalid path exposure mode");
        }
        modes.push_back({
            .access = *access,
            .materialization = *materialization,
            .max_bytes = mode.max_bytes,
            .cleanup_policy = *cleanup,
        });
    }
    auto created = state.path_exposures->create(
        supervisor::path_exposure_create_request{
            .request_id = idempotency_key,
            .exposure_id = payload->exposure_id,
            .root_id = payload->root_id,
            .host_path = payload->host_path,
            .display_label = payload->display_label,
            .allowed_modes = std::move(modes),
            .ttl_secs = payload->ttl_secs,
            .allowed_runtime_template_ids = payload->allowed_runtime_template_ids,
        },
        now_ms
    );
    if (!created) {
        return error_response(
            request_id, "path_exposure_rejected", "path exposure creation was rejected"
        );
    }
    const auto inventory = state.path_exposures->list(now_ms);
    const auto projection = std::ranges::find_if(inventory, [&](const auto& exposure) {
        return exposure.exposure_id == created->exposure_id &&
               exposure.generation == created->generation;
    });
    if (projection == inventory.end()) {
        return error_response(
            request_id, "path_exposure_unavailable", "created path exposure is unavailable"
        );
    }
    auto result = encode_json(
        path_exposure_result{
            .exposure = project_path_exposure(*projection),
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_list_path_exposures(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.path_exposures) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    if (params.idempotency_key.has_value() || params.payload.str != "null") {
        return error_response(
            request_id, "invalid_request", "path exposure listing requires a null read-only payload"
        );
    }
    std::vector<path_exposure_projection> projections;
    for (const auto& exposure : state.path_exposures->list(now_ms)) {
        projections.push_back(project_path_exposure(exposure));
    }
    auto result = encode_json(
        path_exposure_list_result{
            .exposures = std::move(projections),
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto handle_revoke_path_exposure(
    receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params,
    std::uint64_t now_ms
) -> std::expected<std::string, std::string> {
    if (!state.path_exposures) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    const auto idempotency_key = params.idempotency_key.value_or(std::string{});
    auto payload = decode_strict<revoke_path_exposure_request>(params.payload.str);
    if (!valid_identifier(idempotency_key) || !payload) {
        return error_response(request_id, "invalid_request", "invalid path exposure revocation");
    }
    auto revoked = state.path_exposures->revoke(
        idempotency_key, payload->exposure_id, payload->generation, now_ms
    );
    if (!revoked) {
        return error_response(
            request_id, "path_exposure_rejected", "path exposure revocation was rejected"
        );
    }
    const auto inventory = state.path_exposures->list(now_ms);
    const auto projection = std::ranges::find_if(inventory, [&](const auto& exposure) {
        return exposure.exposure_id == payload->exposure_id &&
               exposure.generation == payload->generation;
    });
    if (projection == inventory.end()) {
        return error_response(
            request_id, "path_exposure_unavailable", "revoked path exposure is unavailable"
        );
    }
    auto result = encode_json(
        path_exposure_result{
            .exposure = project_path_exposure(*projection),
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

auto retained_change_kind_name(supervisor::path_change_kind kind) -> std::string_view {
    switch (kind) {
    case supervisor::path_change_kind::create:
        return "create";
    case supervisor::path_change_kind::modify:
        return "modify";
    case supervisor::path_change_kind::rename:
        return "rename";
    case supervisor::path_change_kind::remove:
        return "remove";
    }
    return "";
}

auto handle_inspect_retained_changes(
    const receipt_audit_protocol::implementation& state,
    std::string_view request_id,
    const rpc_params& params
) -> std::expected<std::string, std::string> {
    if (state.materialization_root.empty()) {
        return error_response(request_id, "method_not_found", "control method is unavailable");
    }
    if (params.idempotency_key.has_value()) {
        return error_response(request_id, "invalid_request", "inspection is read-only");
    }
    auto payload = decode_strict<retained_change_inspect_request>(params.payload.str);
    if (!payload || !valid_identifier(payload->session_id) ||
        !valid_identifier(payload->exposure_id) || payload->limit == 0 || payload->limit > 256U) {
        return error_response(request_id, "invalid_request", "invalid retained change request");
    }
    auto manifest = supervisor::inspect_retained_change_stage(
        state.materialization_root, payload->session_id, payload->exposure_id
    );
    if (!manifest || payload->offset > manifest->changes.size()) {
        return error_response(
            request_id, "retained_changes_unavailable", "retained changes are unavailable"
        );
    }
    const auto begin = static_cast<std::size_t>(payload->offset);
    const auto end =
        std::min(manifest->changes.size(), begin + static_cast<std::size_t>(payload->limit));
    std::vector<retained_change_entry> changes;
    for (auto index = begin; index < end; ++index) {
        const auto& change = manifest->changes[index];
        changes.push_back({
            .kind = std::string{retained_change_kind_name(change.kind)},
            .path = change.path,
            .previous_path = change.previous_path,
            .before_digest = change.before_digest,
            .after_digest = change.after_digest,
            .before_bytes = change.before_bytes,
            .after_bytes = change.after_bytes,
            .before_mode = change.before_mode,
            .after_mode = change.after_mode,
            .directory = change.directory,
        });
    }
    auto result = encode_json(
        retained_change_inspect_result{
            .session_id = manifest->session_id,
            .exposure_id = manifest->exposure_id,
            .generation = manifest->generation,
            .scope_digest = manifest->scope_digest,
            .source_identity_digest = manifest->source_identity_digest,
            .max_bytes = manifest->max_bytes,
            .directory = manifest->directory,
            .baseline_tree_digest = manifest->baseline_tree_digest,
            .staged_tree_digest = manifest->staged_tree_digest,
            .manifest_digest = manifest->manifest_digest,
            .created = manifest->created,
            .modified = manifest->modified,
            .renamed = manifest->renamed,
            .removed = manifest->removed,
            .before_bytes = manifest->before_bytes,
            .after_bytes = manifest->after_bytes,
            .total_changes = manifest->changes.size(),
            .next_offset =
                end < manifest->changes.size() ? std::optional<std::uint64_t>{end} : std::nullopt,
            .changes = std::move(changes),
        }
    );
    if (!result) {
        return std::unexpected(result.error());
    }
    return success_response(request_id, std::move(*result));
}

} // namespace glove::control::receipt_handlers
