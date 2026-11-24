// Synthetic agent. Two modes:
//
//   --mode=server (default) — acts as an MCP server. Reads requests from
//      stdin, writes hand-rolled responses for initialize / tools/list /
//      tools/call. Used by Phase 2's spawner test to validate the perimeter
//      without involving a kernel.
//
//   --mode=client — acts as an MCP client. Drives an initialize handshake,
//      then `tools/list`, then `tools/call yams.mcp.echo` with a canned
//      argument; verifies the echoed text appears in the result. Exits 0 on
//      success, non-zero on any verification failure. Used by Phase 4's
//      end-to-end `glove run` test where the kernel is the counterparty.
//
// On macOS the production spawner wraps both modes in sandbox-exec. Direct
// test launches retain a small self-sandbox fallback so the fixture is never
// accidentally exercised with ambient host access.

#include "glove/version.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

#if defined(__APPLE__)
extern "C" int sandbox_init_with_parameters(
    const char* profile, uint64_t flags, const char* const parameters[], char** errorbuf
);
#endif

namespace {

#if defined(__APPLE__)
constexpr std::string_view minimal_sbpl_profile =
    R"((version 1)
       (deny default)
       (allow file-read*  (subpath "/usr/lib"))
       (allow file-read*  (subpath "/System/Library"))
       (allow file-read*  (subpath "/Library/Apple/usr/lib"))
       (allow file-read-metadata)
       (allow process*)
       (allow signal (target self))
       (allow ipc-posix-shm)
       (allow sysctl-read))";
#endif

auto self_sandbox() -> bool {
#if defined(__APPLE__)
    // The spawner now applies an SBPL profile via sandbox-exec before we run
    // (Phase 5). When it has, a second sandbox_init would fail — so detect that
    // and treat the perimeter as already in place.
    if (const char* s = std::getenv("GLOVE_SANDBOXED"); s != nullptr && *s != '\0') {
        return true;
    }
    char* err = nullptr;
    const int rc =
        sandbox_init_with_parameters(std::string{minimal_sbpl_profile}.c_str(), 0, nullptr, &err);
    if (rc != 0) {
        std::fprintf(stderr, "synthetic_agent: sandbox_init failed: %s\n", err ? err : "unknown");
        return false;
    }
    return true;
#else
    return true; // Linux containment is installed by the clone3 spawner.
#endif
}

void write_line(std::string_view line) {
    std::cout.write(line.data(), static_cast<std::streamsize>(line.size()));
    std::cout.put('\n');
    std::cout.flush();
}

auto extract_id(std::string_view frame) -> long long {
    auto pos = frame.find("\"id\":");
    if (pos == std::string_view::npos) {
        return 0;
    }
    pos += 5;
    while (pos < frame.size() && (frame[pos] == ' ' || frame[pos] == '\t')) {
        ++pos;
    }
    long long id = 0;
    bool negative = false;
    if (pos < frame.size() && frame[pos] == '-') {
        negative = true;
        ++pos;
    }
    while (pos < frame.size() && frame[pos] >= '0' && frame[pos] <= '9') {
        id = id * 10 + (frame[pos] - '0');
        ++pos;
    }
    return negative ? -id : id;
}

void respond_initialize(long long id) {
    std::string out = R"({"jsonrpc":"2.0","id":)";
    out.append(std::to_string(id));
    out.append(R"(,"result":{"protocolVersion":"2025-06-18",)");
    out.append(R"("serverInfo":{"name":"glove-synthetic-agent","version":")");
    out.append(glove::version);
    out.append(R"("},)");
    out.append(R"("capabilities":{"tools":{}}}})");
    write_line(out);
}

void respond_tools_list(long long id) {
    std::string out = R"({"jsonrpc":"2.0","id":)";
    out.append(std::to_string(id));
    out.append(R"(,"result":{"tools":[)");
    out.append(R"({"name":"noop","description":"Do nothing.","inputSchema":{"type":"object"}})");
    out.append(R"(]}})");
    write_line(out);
}

void respond_tools_call_noop(long long id) {
    std::string out = R"({"jsonrpc":"2.0","id":)";
    out.append(std::to_string(id));
    out.append(R"(,"result":{"content":[{"type":"text","text":"noop ok"}],"isError":false}})");
    write_line(out);
}

void respond_method_not_found(long long id, std::string_view method) {
    std::string out = R"({"jsonrpc":"2.0","id":)";
    out.append(std::to_string(id));
    out.append(R"(,"error":{"code":-32601,"message":"method not found: )");
    out.append(method);
    out.append(R"("}})");
    write_line(out);
}

auto extract_method(std::string_view frame) -> std::string_view {
    constexpr std::string_view key = "\"method\":\"";
    auto pos = frame.find(key);
    if (pos == std::string_view::npos) {
        return {};
    }
    pos += key.size();
    auto end = frame.find('"', pos);
    if (end == std::string_view::npos) {
        return {};
    }
    return frame.substr(pos, end - pos);
}

auto run_server_mode() -> int {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            continue;
        }
        const long long id = extract_id(line);
        const std::string_view method = extract_method(line);
        if (method == "initialize") {
            respond_initialize(id);
        } else if (method == "notifications/initialized") {
            // No response per JSON-RPC notification semantics.
        } else if (method == "tools/list") {
            respond_tools_list(id);
        } else if (method == "tools/call") {
            respond_tools_call_noop(id);
        } else {
            respond_method_not_found(id, method);
        }
    }
    return 0;
}

// --- Client mode helpers ----------------------------------------------------

auto read_response() -> std::string {
    std::string line;
    if (!std::getline(std::cin, line)) {
        return {};
    }
    return line;
}

auto contains_substring(std::string_view haystack, std::string_view needle) -> bool {
    return haystack.find(needle) != std::string_view::npos;
}

// Test sequence: targeted at the glove_run_yams_test. Hardcodes the call to
// yams.mcp.echo because that's what Phase 4's end-to-end test exercises.
// Future phases can parameterise via CLI args if more agents need this.
auto run_client_mode() -> int {
    std::string init_req = R"({"jsonrpc":"2.0","id":1,"method":"initialize",)"
                           R"("params":{"protocolVersion":"2025-06-18",)"
                           R"("capabilities":{},)"
                           R"("clientInfo":{"name":"glove-synthetic","version":")";
    init_req.append(glove::version);
    init_req.append(R"("}}})");
    write_line(init_req);
    auto reply = read_response();
    if (reply.empty() || !contains_substring(reply, "\"id\":1")) {
        std::fprintf(stderr, "synthetic_agent: bad initialize reply: %s\n", reply.c_str());
        return 10;
    }
    if (!contains_substring(reply, "\"protocolVersion\":\"2025")) {
        std::fprintf(stderr, "synthetic_agent: missing protocolVersion: %s\n", reply.c_str());
        return 11;
    }

    write_line(R"({"jsonrpc":"2.0","method":"notifications/initialized"})");

    write_line(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    reply = read_response();
    if (reply.empty() || !contains_substring(reply, "\"id\":2")) {
        std::fprintf(stderr, "synthetic_agent: bad tools/list reply: %s\n", reply.c_str());
        return 12;
    }
    if (!contains_substring(reply, "yams.mcp.echo")) {
        std::fprintf(
            stderr, "synthetic_agent: yams.mcp.echo not in tools list: %s\n", reply.c_str()
        );
        return 13;
    }

    write_line(
        R"({"jsonrpc":"2.0","id":3,"method":"tools/call",)"
        R"("params":{"name":"yams.mcp.echo",)"
        R"("arguments":{"text":"glove-says-hi"}}})"
    );
    reply = read_response();
    if (reply.empty() || !contains_substring(reply, "\"id\":3")) {
        std::fprintf(stderr, "synthetic_agent: bad tools/call reply: %s\n", reply.c_str());
        return 14;
    }
    if (!contains_substring(reply, "glove-says-hi")) {
        std::fprintf(stderr, "synthetic_agent: echoed text missing: %s\n", reply.c_str());
        return 15;
    }
    return 0;
}

} // namespace

auto main(int argc, char** argv) -> int {
    if (!self_sandbox()) {
        return 2;
    }

    std::string_view mode = "server";
    for (int i = 1; i < argc; ++i) {
        std::string_view a{argv[i]};
        constexpr std::string_view prefix = "--mode=";
        if (a.starts_with(prefix)) {
            mode = a.substr(prefix.size());
        }
    }

    if (mode == "server") {
        return run_server_mode();
    }
    if (mode == "client") {
        return run_client_mode();
    }
    std::fprintf(
        stderr, "synthetic_agent: unknown --mode=%.*s\n", static_cast<int>(mode.size()), mode.data()
    );
    return 3;
}
