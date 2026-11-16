#include "glove/audit/sink.hpp"
#include "glove/kernel/extension.hpp"
#include "glove/kernel/mcp_extension.hpp"
#include "glove/kernel/registry.hpp"
#include "glove/kernel/server.hpp"
#include "glove/mcp/client.hpp"
#include "glove/mcp/messages.hpp"
#include "glove/mcp/transport.hpp"
#include "glove/policy/engine.hpp"
#include "glove/reflect/json_codec.hpp"

#include "src/mcp/codec.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t max_input_bytes = 256U * 1024U;
constexpr std::size_t max_frames_per_run = 32U;

auto split_frames(std::string_view stream) -> std::vector<std::string> {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < stream.size() && out.size() < max_frames_per_run) {
        const auto nl = stream.find('\n', pos);
        if (nl == std::string_view::npos) {
            out.emplace_back(stream.substr(pos));
            break;
        }
        out.emplace_back(stream.substr(pos, nl - pos));
        pos = nl + 1U;
    }
    return out;
}

class fuzz_server_transport final : public glove::mcp::transport {
public:
    explicit fuzz_server_transport(std::vector<std::string> incoming)
        : incoming_{std::move(incoming)} {}

    auto send(std::string_view frame) -> std::expected<void, std::string> override {
        sent_.emplace_back(frame);
        return {};
    }

    auto recv() -> std::expected<std::string, std::string> override {
        if (cursor_ >= incoming_.size()) {
            return std::unexpected(std::string{"eof"});
        }
        return incoming_[cursor_++];
    }

    [[nodiscard]] auto sent() const -> const std::vector<std::string>& { return sent_; }

private:
    std::vector<std::string> incoming_;
    std::size_t cursor_ = 0;
    std::vector<std::string> sent_;
};

class fs_guard_extension final : public glove::kernel::extension {
public:
    auto name() const -> std::string_view override { return "fs"; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return std::vector<glove::mcp::tool_descriptor>{
            {"read_file", "Read a workspace file", {}, {}},
            {"write_file", "Denied write", {}, {}},
            {"stat", "Unlisted stat", {}, {}},
        };
    }

    auto invoke(std::string_view tool_name, std::string_view arguments_json)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        if (tool_name != "read_file") {
            std::abort();
        }
        static_cast<void>(glove::reflect::detail::parse_json_object(arguments_json));

        glz::generic doc;
        std::string buf{arguments_json};
        if (glz::read_json(doc, buf) || !doc.is_object()) {
            std::abort();
        }
        const auto& obj = doc.get_object();
        const auto it = obj.find("path");
        if (it == obj.end() || !it->second.is_string()) {
            std::abort();
        }
        auto candidate = std::filesystem::path{it->second.get_string()}.lexically_normal();
        if (!candidate.has_filename() && candidate != candidate.root_path()) {
            candidate = candidate.parent_path();
        }
        const std::filesystem::path root{"/workspace"};
        const auto mismatch =
            std::mismatch(root.begin(), root.end(), candidate.begin(), candidate.end());
        if (!candidate.is_absolute() || mismatch.first != root.end()) {
            std::abort();
        }
        return glove::mcp::tool_call_result{
            glove::mcp::tool_call_status::ok,
            "ok",
            {},
            {},
        };
    }
};

class denied_exec_extension final : public glove::kernel::extension {
public:
    auto name() const -> std::string_view override { return "exec"; }

    auto tools() -> std::expected<std::vector<glove::mcp::tool_descriptor>, std::string> override {
        return std::vector<glove::mcp::tool_descriptor>{
            {"run", "Denied shell execution", {}, {}},
        };
    }

    auto invoke(std::string_view /*tool_name*/, std::string_view /*arguments_json*/)
        -> std::expected<glove::mcp::tool_call_result, std::string> override {
        std::abort();
    }
};

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > max_input_bytes) {
        return 0;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const std::string_view raw{reinterpret_cast<const char*>(data), size};
    const auto sep = raw.find('\x1e');
    const std::string_view agent_raw = sep == std::string_view::npos ? raw : raw.substr(0, sep);
    const std::string_view upstream_raw =
        sep == std::string_view::npos ? std::string_view{} : raw.substr(sep + 1U);

    auto agent_frames = split_frames(agent_raw);
    for (const auto& frame : agent_frames) {
        static_cast<void>(glove::reflect::detail::parse_json_object(frame));
    }

    auto upstream_frames = split_frames(upstream_raw);
    auto upstream_transport = std::make_unique<fuzz_server_transport>(std::move(upstream_frames));

    glove::kernel::registry reg;
    if (!reg.add(std::make_unique<fs_guard_extension>()) ||
        !reg.add(std::make_unique<denied_exec_extension>()) ||
        !reg.add(
            glove::kernel::make_mcp_extension(
                "upstream", glove::mcp::make_client(std::move(upstream_transport))
            )
        )) {
        std::abort();
    }

    std::shared_ptr<glove::policy::engine> policy = glove::policy::make_jsonpath_engine({
        .allow = {"fs.read_file", "fs.write_file", "upstream.echo"},
        .deny = {"fs.write_file", "exec.run"},
        .prefix_rules = {
            {
                .tool_name = "fs.read_file",
                .field = "path",
                .required_prefix = "/workspace/",
            },
        },
    });
    auto audit_sink = glove::audit::make_memory_sink();

    fuzz_server_transport transport{std::move(agent_frames)};
    glove::kernel::server srv{
        transport,
        reg,
        {
            .identity = {.name = "glove-fuzz", .version = "0.0.1"},
            .policy = std::move(policy),
            .audit = audit_sink,
        },
    };
    static_cast<void>(srv.run());

    for (const auto& reply : transport.sent()) {
        auto decoded = glove::mcp::codec::decode_response(reply);
        if (!decoded) {
            std::abort();
        }
        auto listed = glove::mcp::codec::parse_tools_list_result(*decoded);
        if (listed) {
            for (const auto& tool : *listed) {
                if (tool.name == "exec.run" || tool.name == "fs.write_file" ||
                    tool.name == "fs.stat") {
                    std::abort();
                }
            }
        }
    }

    for (const auto& ev : audit_sink->take()) {
        if (ev.what == glove::audit::action::call_tool &&
            ev.status == glove::mcp::tool_call_status::ok && ev.tool_name != "fs.read_file" &&
            ev.tool_name != "upstream.echo") {
            std::abort();
        }
    }

    return 0;
}
