#include "http1_client.hpp"

#include "http_syntax.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::net::http {

namespace {

// A provider never needs more than a handful of interim responses; a peer that
// streams them indefinitely is stalling, not progressing.
constexpr int max_interim_responses = 8;
// A chunk-size line is a hex number plus optional extensions. Anything longer
// is not a chunk header a provider would send.
constexpr std::size_t max_chunk_line_bytes = 1024;

// Pulls bytes from the stream into a local buffer so the parser can look ahead
// for line and head boundaries without reading past the response.
class buffered_reader {
public:
    buffered_reader(byte_stream& stream, std::stop_token stop, byte_stream::deadline until)
        : stream_{&stream}, stop_{std::move(stop)}, until_{until} {}

    // Appends more bytes; false means the peer closed the stream.
    auto fill() -> std::expected<bool, std::string> {
        std::array<char, 16384> chunk{};
        auto got = stream_->read_some(chunk, stop_, until_);
        if (!got) {
            return std::unexpected(got.error());
        }
        if (*got == 0) {
            return false;
        }
        buffer_.append(chunk.data(), *got);
        return true;
    }

    // Reads through the next `terminator`, returning what precedes it. Fails if
    // `limit` bytes arrive without one.
    auto read_until(std::string_view terminator, std::size_t limit)
        -> std::expected<std::string, std::string> {
        std::size_t searched = 0;
        while (true) {
            const auto found = buffer_.find(terminator, searched);
            if (found != std::string::npos) {
                if (found > limit) {
                    return std::unexpected(std::string{"field section too large"});
                }
                std::string line = buffer_.substr(0, found);
                buffer_.erase(0, found + terminator.size());
                return line;
            }
            if (buffer_.size() > limit) {
                return std::unexpected(std::string{"field section too large"});
            }
            searched =
                buffer_.size() >= terminator.size() ? buffer_.size() - terminator.size() + 1 : 0;
            auto more = fill();
            if (!more) {
                return std::unexpected(more.error());
            }
            if (!*more) {
                return std::unexpected(std::string{"connection closed mid-response"});
            }
        }
    }

    // Moves buffered bytes into `out` as they arrive, so a large body is held
    // once rather than staged in the look-ahead buffer and then copied.
    auto read_exact(std::size_t length, std::string& out) -> std::expected<void, std::string> {
        while (true) {
            const auto take = std::min(length, buffer_.size());
            out.append(buffer_, 0, take);
            buffer_.erase(0, take);
            length -= take;
            if (length == 0) {
                return {};
            }
            auto more = fill();
            if (!more) {
                return std::unexpected(more.error());
            }
            if (!*more) {
                return std::unexpected(std::string{"connection closed mid-body"});
            }
        }
    }

private:
    byte_stream* stream_;
    std::stop_token stop_;
    byte_stream::deadline until_;
    std::string buffer_;
};

struct response_head {
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
};

auto parse_status_code(std::string_view digits) -> std::optional<int> {
    if (digits.size() != 3) {
        return std::nullopt;
    }
    int code = 0;
    for (const char c : digits) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        code = code * 10 + (c - '0');
    }
    if (code < 100) {
        return std::nullopt;
    }
    return code;
}

auto parse_response_head(std::string_view raw) -> std::expected<response_head, std::string> {
    if (has_bare_line_break(raw)) {
        return std::unexpected(std::string{"bare CR or LF in response head"});
    }
    const auto line_end = raw.find("\r\n");
    const auto status_line = raw.substr(0, line_end);
    // status-line = HTTP-version SP status-code SP reason-phrase
    if (!status_line.starts_with("HTTP/1.1 ") && !status_line.starts_with("HTTP/1.0 ")) {
        return std::unexpected(std::string{"unsupported response version"});
    }
    // The SP after the code is mandatory even when the reason phrase is empty.
    const auto code = parse_status_code(status_line.substr(9, 3));
    if (!code || status_line.size() < 13 || status_line[12] != ' ') {
        return std::unexpected(std::string{"malformed status line"});
    }
    if (!is_valid_field_value(status_line.substr(13))) {
        return std::unexpected(std::string{"malformed reason phrase"});
    }

    response_head head;
    head.status_code = *code;
    if (line_end == std::string_view::npos) {
        return head;
    }
    std::size_t cursor = line_end + 2U;
    while (cursor < raw.size()) {
        auto next = raw.find("\r\n", cursor);
        if (next == std::string_view::npos) {
            next = raw.size();
        }
        const auto line = raw.substr(cursor, next - cursor);
        cursor = next + 2U;
        if (head.headers.size() >= max_header_count) {
            return std::unexpected(std::string{"too many response header fields"});
        }
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) {
            return std::unexpected(std::string{"malformed response header field"});
        }
        const auto value = trim_ows(line.substr(colon + 1));
        if (!is_valid_field_value(value)) {
            return std::unexpected(std::string{"invalid response header value"});
        }
        head.headers.emplace_back(std::string{line.substr(0, colon)}, std::string{value});
    }
    return head;
}

enum class body_framing : std::uint8_t {
    none,
    chunked,
    length,
};

struct framing_decision {
    body_framing framing = body_framing::none;
    std::size_t length = 0;
};

// RFC 9112 6.3. Transfer-Encoding and Content-Length together, a coding other
// than plain chunked, a repeated length, or no framing at all are ambiguities;
// refuse them rather than guess where the provider's body ends.
auto decide_framing(const response_head& head, std::string_view request_method)
    -> std::expected<framing_decision, std::string> {
    if (request_method == "HEAD" || head.status_code == 204 || head.status_code == 304) {
        return framing_decision{.framing = body_framing::none, .length = 0};
    }
    std::optional<std::string_view> transfer_encoding;
    std::optional<std::string_view> content_length;
    for (const auto& [name, value] : head.headers) {
        const auto lowered = lower_ascii(name);
        if (lowered == "transfer-encoding") {
            if (transfer_encoding) {
                return std::unexpected(std::string{"repeated transfer-encoding"});
            }
            transfer_encoding = value;
        } else if (lowered == "content-length") {
            if (content_length) {
                return std::unexpected(std::string{"repeated content-length"});
            }
            content_length = value;
        }
    }
    if (transfer_encoding && content_length) {
        return std::unexpected(std::string{"both transfer-encoding and content-length"});
    }
    if (transfer_encoding) {
        if (lower_ascii(std::string{*transfer_encoding}) != "chunked") {
            return std::unexpected(std::string{"unsupported transfer-encoding"});
        }
        return framing_decision{.framing = body_framing::chunked, .length = 0};
    }
    if (content_length) {
        auto length = parse_content_length(*content_length, max_response_body_bytes);
        if (!length) {
            return std::unexpected(length.error());
        }
        return framing_decision{.framing = body_framing::length, .length = *length};
    }
    // A close-delimited body cannot be told apart from one cut short by a
    // dropped connection, and the endpoint would re-frame a truncated body as
    // complete. Providers always frame their bodies, so refuse instead.
    return std::unexpected(std::string{"response body has no length or chunked framing"});
}

auto hex_value(char c) -> int {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

auto parse_chunk_size(std::string_view line, std::size_t remaining_budget)
    -> std::expected<std::size_t, std::string> {
    const auto extension = line.find(';');
    const auto digits = trim_ows(line.substr(0, extension));
    if (digits.empty()) {
        return std::unexpected(std::string{"empty chunk size"});
    }
    if (extension != std::string_view::npos && !is_valid_field_value(line.substr(extension + 1))) {
        return std::unexpected(std::string{"invalid chunk extension"});
    }
    std::size_t size = 0;
    for (const char c : digits) {
        const int digit = hex_value(c);
        if (digit < 0) {
            return std::unexpected(std::string{"invalid chunk size"});
        }
        const auto value = static_cast<std::size_t>(digit);
        if (value > remaining_budget || size > (remaining_budget - value) / 16U) {
            return std::unexpected(std::string{"response body too large"});
        }
        size = size * 16U + value;
    }
    return size;
}

auto read_chunked(buffered_reader& reader, std::string& body) -> std::expected<void, std::string> {
    while (true) {
        auto line = reader.read_until("\r\n", max_chunk_line_bytes);
        if (!line) {
            return std::unexpected(line.error());
        }
        if (has_bare_line_break(*line)) {
            return std::unexpected(std::string{"bare CR or LF in chunk header"});
        }
        auto size = parse_chunk_size(*line, max_response_body_bytes - body.size());
        if (!size) {
            return std::unexpected(size.error());
        }
        if (*size == 0) {
            break;
        }
        if (auto data = reader.read_exact(*size, body); !data) {
            return std::unexpected(data.error());
        }
        std::string terminator;
        if (auto crlf = reader.read_exact(2, terminator); !crlf) {
            return std::unexpected(crlf.error());
        }
        if (terminator != "\r\n") {
            return std::unexpected(std::string{"chunk not terminated by CRLF"});
        }
    }
    // Trailer fields are dropped: the endpoint re-frames the body with its own
    // Content-Length, so nothing downstream could carry them anyway.
    std::size_t trailer_bytes = 0;
    while (true) {
        if (trailer_bytes >= max_head_bytes) {
            return std::unexpected(std::string{"field section too large"});
        }
        auto line = reader.read_until("\r\n", max_head_bytes - trailer_bytes);
        if (!line) {
            return std::unexpected(line.error());
        }
        if (line->empty()) {
            return {};
        }
        trailer_bytes += line->size() + 2U;
    }
}

// Fields this serializer emits itself or that change framing, routing, or
// the credential. A caller's copy would mean two Hosts, two framings, or two
// credentials on the wire, so one is refused rather than dropped silently.
constexpr auto serializer_owned_fields = std::to_array<std::string_view>({
    "host",
    "content-length",
    "transfer-encoding",
    "te",
    "trailer",
    "connection",
    "keep-alive",
    "upgrade",
    "expect",
    "proxy-connection",
    "proxy-authorization",
    "x-api-key",
    "authorization",
});

auto is_serializer_owned(std::string_view lowered_name) -> bool {
    return std::ranges::find(serializer_owned_fields, lowered_name) !=
           serializer_owned_fields.end();
}

auto credential_field(credential_scheme scheme, std::string_view secret) -> std::string {
    switch (scheme) {
    case credential_scheme::x_api_key:
        return "x-api-key: " + std::string{secret};
    case credential_scheme::bearer:
        return "Authorization: Bearer " + std::string{secret};
    }
    return {};
}

} // namespace

auto serialize_request(const upstream_request& request, credential_scheme scheme)
    -> std::expected<std::string, std::string> {
    if (!is_token(request.method)) {
        return std::unexpected(std::string{"invalid request method"});
    }
    // Visible ASCII only: a space, tab, or obs-text byte in the request line
    // could split it differently at the provider.
    if (request.target.empty() || request.target.front() != '/' ||
        !std::ranges::all_of(request.target, [](char c) { return c > 0x20 && c < 0x7f; })) {
        return std::unexpected(std::string{"invalid request target"});
    }
    if (request.upstream_host.empty() || !is_token(request.upstream_host)) {
        return std::unexpected(std::string{"invalid upstream host"});
    }
    // The secret is never echoed into an error: a malformed one is reported by
    // shape only.
    if (request.secret_token.empty() || !is_valid_field_value(request.secret_token) ||
        trim_ows(request.secret_token).size() != request.secret_token.size()) {
        return std::unexpected(std::string{"provider credential is not a valid field value"});
    }

    std::string out;
    out.reserve(request.body.size() + 512U);
    out += request.method;
    out += ' ';
    out += request.target;
    out += " HTTP/1.1\r\nHost: ";
    out += request.upstream_host;
    if (request.upstream_port != 443) {
        out += ':';
        out += std::to_string(request.upstream_port);
    }
    out += "\r\n";
    for (const auto& [name, value] : request.headers) {
        if (!is_token(name) || !is_valid_field_value(value)) {
            return std::unexpected(std::string{"invalid forwarded header field"});
        }
        if (is_serializer_owned(lower_ascii(name))) {
            return std::unexpected(std::string{"forwarded header field is owned by the transport"});
        }
        out += name;
        out += ": ";
        out += value;
        out += "\r\n";
    }
    out += credential_field(scheme, request.secret_token);
    out += "\r\nContent-Length: ";
    out += std::to_string(request.body.size());
    out += "\r\nConnection: close\r\n\r\n";
    out += request.body;
    return out;
}

auto read_response(
    byte_stream& stream,
    std::string_view request_method,
    std::stop_token stop,
    byte_stream::deadline until
) -> std::expected<upstream_response, std::string> {
    buffered_reader reader{stream, std::move(stop), until};

    response_head head;
    for (int interim = 0;;) {
        auto raw = reader.read_until("\r\n\r\n", max_head_bytes);
        if (!raw) {
            return std::unexpected(raw.error());
        }
        auto parsed = parse_response_head(*raw);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        if (parsed->status_code >= 200) {
            head = std::move(*parsed);
            break;
        }
        // 101 would hand the connection to another protocol; this client
        // never asks for an upgrade, so one is a protocol violation.
        if (parsed->status_code == 101) {
            return std::unexpected(std::string{"unexpected protocol upgrade"});
        }
        if (++interim > max_interim_responses) {
            return std::unexpected(std::string{"too many interim responses"});
        }
    }
    if (head.status_code > 599) {
        return std::unexpected(std::string{"status code out of range"});
    }

    auto framing = decide_framing(head, request_method);
    if (!framing) {
        return std::unexpected(framing.error());
    }

    upstream_response response;
    response.status_code = head.status_code;
    switch (framing->framing) {
    case body_framing::none:
        break;
    case body_framing::chunked:
        if (auto body = read_chunked(reader, response.body); !body) {
            return std::unexpected(body.error());
        }
        break;
    case body_framing::length:
        if (auto body = reader.read_exact(framing->length, response.body); !body) {
            return std::unexpected(body.error());
        }
        break;
    }
    response.headers = std::move(head.headers);
    return response;
}

} // namespace glove::net::http
