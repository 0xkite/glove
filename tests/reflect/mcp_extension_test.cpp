#include "glove/kernel/registry.hpp"
#include "glove/kernel/server.hpp"
#include "glove/policy/decision.hpp"
#include "glove/policy/engine.hpp"
#include "glove/reflect/codegen.hpp"
#include "glove/reflect/extension.hpp"

#include "tests/kernel/mock_pair.hpp"

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>

namespace {

#if defined(GLOVE_HAS_REFLECTION)
struct[[= glove::reflect::tool_meta{"read_elf", "Inspect ELF headers of a pinned binary"}]]
    read_elf_args {
    [[= glove::reflect::param_meta{
        "path", "Read-only quarantined artifact path", true
    }]] std::string path;
    [[= glove::reflect::param_meta{"sections", "Include section table", false}]] bool sections =
        false;
    [[= glove::reflect::param_meta{
        "max_symbols", "Maximum symbol entries", false
    }]] std::optional<std::uint32_t>
        max_symbols;
};
#endif

} // namespace

int main() {
#if defined(GLOVE_HAS_REFLECTION)
    auto ext = std::make_unique<glove::reflect::reflected_extension>("re");
    assert(ext->add_tool<read_elf_args>(
                  [](const read_elf_args& args) {
                      return glove::mcp::tool_call_result{
                          .status = glove::mcp::tool_call_status::ok,
                          .content = args.path + (args.sections ? ":sections" : ":header"),
                          .structured_json = {},
                          .error_message = {},
                      };
                  }
    ).has_value());
    assert(!ext->add_tool<read_elf_args>(
                   [](const read_elf_args&) { return glove::mcp::tool_call_result{}; }
    ).has_value());

    glove::kernel::registry reg;
    assert(reg.add(std::move(ext)).has_value());

    auto policy = glove::policy::make_allow_list_engine({
        .allow = {"re.read_elf"},
        .deny = {},
        .default_decision = glove::policy::decision::deny,
    });
    glove::testing::mock_pair pair;

    glove::kernel::server srv(
        pair.kernel_side(),
        reg,
        glove::kernel::server::options{
            .identity = {.name = "glove-test", .version = "0.0.1"},
            .policy = std::shared_ptr<glove::policy::engine>{std::move(policy)},
            .audit = nullptr,
        }
    );

    std::thread server_thread([&]() { (void)srv.run(); });

    auto& agent = pair.agent_side();
    assert(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})"
            )
            .has_value()
    );
    auto init_resp = agent.recv();
    assert(init_resp.has_value());
    assert(init_resp->find("glove-test") != std::string::npos);

    assert(agent.send(R"({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})").has_value());
    auto list_resp = agent.recv();
    assert(list_resp.has_value());
    assert(list_resp->find("re.read_elf") != std::string::npos);
    assert(list_resp->find("Read-only quarantined artifact path") != std::string::npos);

    assert(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"re.read_elf","arguments":{"path":"/quarantine/blobs/abc","sections":true}}})"
            )
            .has_value()
    );
    auto call_resp = agent.recv();
    assert(call_resp.has_value());
    assert(call_resp->find("/quarantine/blobs/abc:sections") != std::string::npos);

    assert(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"re.read_elf","arguments":{"path":123}}})"
            )
            .has_value()
    );
    auto bad_resp = agent.recv();
    assert(bad_resp.has_value());
    assert(bad_resp->find("isError") != std::string::npos);

    assert(
        agent
            .send(
                R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"re.read_elf","arguments":{}}})"
            )
            .has_value()
    );
    auto missing_resp = agent.recv();
    assert(missing_resp.has_value());
    assert(missing_resp->find("isError") != std::string::npos);

    pair.close_agent_to_kernel();
    server_thread.join();
#else
    static_assert(!glove::reflect::reflection_available);
#endif
    return 0;
}
