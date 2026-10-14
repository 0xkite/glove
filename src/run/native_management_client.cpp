// Client side of the management protocol v1: capability admission, one
// authenticated request per connection, strict result decoding.
#include "native_management_wire.hpp"

namespace glove::run::detail {
using namespace management_detail; // NOLINT(google-build-using-namespace)

auto read_management_capability(
    const std::filesystem::path& control_directory, std::string_view session
) -> std::expected<std::pair<std::string, std::string>, management_client_failure> {
    const auto fail = [](management_client_error code, std::string message) {
        return std::unexpected(
            management_client_failure{.code = code, .message = std::move(message)}
        );
    };
    auto control = pin_parent(control_directory);
    if (!control) {
        return fail(management_client_error::capability_unavailable, control.error());
    }
    descriptor file{
        ::openat(control->fd(), capability_name.data(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    };
    struct stat info{};
    if (file.get() < 0 || ::fstat(file.get(), &info) != 0 || !private_file(info, 0600) ||
        info.st_size <= 0 || info.st_size > 512) {
        return fail(
            management_client_error::capability_unavailable, "management capability unavailable"
        );
    }
    std::string bytes(static_cast<std::size_t>(info.st_size), '\0');
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::pread(
            file.get(), bytes.data() + offset, bytes.size() - offset, static_cast<off_t>(offset)
        );
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return fail(
                management_client_error::capability_unavailable, "cannot read management capability"
            );
        }
        offset += static_cast<std::size_t>(count);
    }
    std::array<std::string, 3> fields;
    std::size_t field = 0;
    for (const char ch : bytes) {
        if (ch == '\n') {
            if (++field > 3) {
                break;
            }
            continue;
        }
        if (field < 3) {
            fields[field].push_back(ch);
        }
    }
    if (field != 3 || fields[0] != session || !valid_epoch(fields[1]) ||
        !valid_checkpoint_id(fields[2])) {
        return fail(
            management_client_error::capability_unavailable, "management capability is malformed"
        );
    }
    return std::pair{fields[1], fields[2]};
}

auto render_management_request(
    std::string_view session,
    std::string_view epoch,
    std::uint64_t observed_generation,
    std::string_view request_id,
    session_operation op,
    const std::optional<std::string>& checkpoint
) -> std::expected<std::string, std::string> {
    std::string json;
    if (checkpoint) {
        const management_wire::request_out_checkpoint frame{
            .v = 1,
            .type = "request",
            .session = std::string{session},
            .epoch = std::string{epoch},
            .generation = format_generation(observed_generation),
            .request = std::string{request_id},
            .op = std::string{to_string(op)},
            .checkpoint = *checkpoint
        };
        if (glz::write_json(frame, json)) {
            return std::unexpected("cannot encode management request");
        }
    } else {
        const management_wire::request_out frame{
            .v = 1,
            .type = "request",
            .session = std::string{session},
            .epoch = std::string{epoch},
            .generation = format_generation(observed_generation),
            .request = std::string{request_id},
            .op = std::string{to_string(op)}
        };
        if (glz::write_json(frame, json)) {
            return std::unexpected("cannot encode management request");
        }
    }
    return json;
}

auto management_request_raw(
    const std::filesystem::path& control_directory,
    std::string_view session,
    std::string_view body,
    std::chrono::milliseconds timeout
) -> std::expected<management_result, management_client_failure> {
    const auto fail = [](management_client_error code, std::string message) {
        return std::unexpected(
            management_client_failure{.code = code, .message = std::move(message)}
        );
    };
    auto capability = read_management_capability(control_directory, session);
    if (!capability) {
        return std::unexpected(capability.error());
    }
    const auto path = control_directory / std::string{socket_name};
    auto address = sockaddr_for(path);
    if (!address) {
        return fail(management_client_error::socket_missing, "management socket path too long");
    }
    descriptor fd{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (fd.get() < 0) {
        return fail(management_client_error::io, "cannot create client socket");
    }
    if (::connect(
            fd.get(),
            reinterpret_cast<const ::sockaddr*>(&*address),
            static_cast<::socklen_t>(sizeof(*address))
        ) != 0) {
        const int error = errno;
        if (error == ENOENT) {
            return fail(
                management_client_error::socket_missing, "management socket name is absent"
            );
        }
        if (error == ECONNREFUSED) {
            // A pathname with no acceptor: the owner is gone or its listener is
            // lost. Neither is liveness evidence and nothing is resurrected.
            return fail(
                management_client_error::connection_refused, "no live acceptor at management socket"
            );
        }
        return fail(management_client_error::io, std::string{"connect: "} + std::strerror(error));
    }
    if (!verify_peer(fd.get())) {
        return fail(management_client_error::peer_identity, "management peer uid mismatch");
    }
    if (!make_nonblocking(fd.get())) {
        return fail(management_client_error::io, "cannot prepare client socket");
    }
    const auto deadline = clock_type::now() + timeout;
    const std::stop_token no_stop;
    std::string auth = "{\"v\":1,\"type\":\"auth\",\"session\":\"" + std::string{session} +
                       "\",\"epoch\":\"" + capability->first + "\",\"capability\":\"" +
                       capability->second + "\"}";
    if (!write_frame(fd.get(), auth, no_stop, deadline)) {
        return fail(management_client_error::io, "cannot send authentication");
    }
    auto ready_body = read_frame(fd.get(), no_stop, deadline);
    if (!ready_body) {
        return fail(
            management_client_error::authentication_refused, "authentication closed without ready"
        );
    }
    ready_frame ready;
    if (glz::read<strict_options>(ready, *ready_body) || ready.v != 1 || ready.type != "ready" ||
        ready.session != session || ready.epoch != capability->first) {
        return fail(management_client_error::malformed, "malformed ready frame");
    }
    if (!write_frame(fd.get(), body, no_stop, deadline)) {
        return fail(management_client_error::io, "cannot send request");
    }
    auto result_body = read_frame(fd.get(), no_stop, deadline);
    if (!result_body) {
        return fail(management_client_error::timeout, "no result frame before deadline");
    }
    if (!bounded_json_object(*result_body, 8)) {
        return fail(management_client_error::malformed, "malformed result frame");
    }
    result_frame frame;
    if (glz::read<closed_options>(frame, *result_body) || frame.v != 1 || frame.type != "result" ||
        frame.session != session || frame.epoch != capability->first) {
        return fail(
            management_client_error::malformed, "result frame disagrees with session/epoch"
        );
    }
    auto generation = parse_generation(frame.generation);
    auto op = parse_session_operation(frame.op);
    auto state = parse_phase(frame.state);
    auto history = parse_history(frame.history);
    auto effects = parse_effects(frame.effects);
    auto code = parse_code(frame.code);
    if (!generation || !op || !state || !history || !effects || !code ||
        !valid_request_id(frame.request) ||
        (frame.checkpoint && !valid_checkpoint_id(*frame.checkpoint))) {
        return fail(management_client_error::malformed, "result frame fields are malformed");
    }
    return management_result{
        .session = frame.session,
        .epoch = frame.epoch,
        .generation = *generation,
        .request = frame.request,
        .op = *op,
        .state = *state,
        .history = *history,
        .checkpoint = frame.checkpoint,
        .effects = *effects,
        .code = *code,
        .final = frame.final
    };
}

auto management_request_once(
    const std::filesystem::path& control_directory,
    std::string_view session,
    const management_request& request,
    std::chrono::milliseconds timeout
) -> std::expected<management_result, management_client_failure> {
    auto capability = read_management_capability(control_directory, session);
    if (!capability) {
        return std::unexpected(capability.error());
    }
    auto body = render_management_request(
        session,
        capability->first,
        request.observed_generation,
        request.request,
        request.op,
        request.checkpoint
    );
    if (!body) {
        return std::unexpected(
            management_client_failure{
                .code = management_client_error::malformed, .message = body.error()
            }
        );
    }
    return management_request_raw(control_directory, session, *body, timeout);
}

} // namespace glove::run::detail
