#include "claude_history.hpp"
#include "json_shape.hpp"

#include <cstddef>
#include <cstdio>
#include <string>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using namespace glove::run::detail;

const std::string session = "0f3c1a2b-4d5e-4f60-8a71-92b3c4d5e6f7";
const std::string u1 = "11111111-1111-4111-8111-111111111111";
const std::string u2 = "22222222-2222-4222-8222-222222222222";
const std::string u3 = "33333333-3333-4333-8333-333333333333";
const std::string u4 = "44444444-4444-4444-8444-444444444444";

auto chain_uuid(std::size_t index) -> std::string {
    constexpr char digits[] = "0123456789abcdef";
    std::string prefix(8, '0');
    for (std::size_t position = prefix.size(); index != 0 && position != 0; --position) {
        prefix[position - 1] = digits[index & 0xf];
        index >>= 4;
    }
    return prefix + "-1111-4111-8111-111111111111";
}

auto line(std::string type, std::string uuid, std::string parent, std::string extra = {})
    -> std::string {
    std::string text = "{\"type\":\"" + type + "\",\"uuid\":\"" + uuid +
                       "\",\"parentUuid\":" + (parent.empty() ? "null" : "\"" + parent + "\"") +
                       ",\"sessionId\":\"" + session + "\",\"version\":\"2.1.296\"";
    if (!extra.empty()) {
        text += "," + extra;
    }
    return text + "}\n";
}

auto binding() -> claude_history_binding {
    return {.conversation_id = session, .runtime_version = "2.1.296"};
}

auto shape_guard() -> int {
    REQUIRE(bounded_json_object("{}", 1));
    REQUIRE(bounded_json_object(R"({"a":[1,2,{"b":null}],"c":"x\"y","d":-1.5e3,"e":true})", 4));
    REQUIRE(!bounded_json_object(R"([1])", 4));
    REQUIRE(!bounded_json_object(R"({"a":1,"a":2})", 4));
    REQUIRE(!bounded_json_object(R"({"a":1} x)", 4));
    REQUIRE(!bounded_json_object(R"({"a":{"b":{"c":1}}})", 2));
    REQUIRE(bounded_json_object(R"({"a":{"b":{"c":1}}})", 3));
    REQUIRE(!bounded_json_object("{\"a\":\"\x01\"}", 4));
    REQUIRE(!bounded_json_object(R"({"a":01})", 4));
    REQUIRE(!bounded_json_object(R"({"a":1,})", 4));
    REQUIRE(!bounded_json_object("", 4));
    return 0;
}

auto accepted_history() -> int {
    const std::string history =
        line(
            "user", u1, "", "\"message\":{\"role\":\"user\",\"content\":\"ping\"},\"cwd\":\"/w\""
        ) +
        line(
            "assistant",
            u2,
            u1,
            "\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"pong\"}"
            "]}"
        );
    auto summary = validate_claude_history(history, binding());
    REQUIRE(summary && summary->entries == 2);
    // Observed 2.1.296 shape: attachments precede the user entry they chain
    // from, and identity-less session records are interleaved.
    const std::string observed =
        "{\"type\":\"last-prompt\",\"leafUuid\":\"" + u2 + "\",\"sessionId\":\"" + session +
        "\"}\n" + "{\"type\":\"atis-latch\",\"atis\":\"\",\"sessionId\":\"" + session + "\"}\n" +
        line("attachment", u3, u1, "\"attachment\":{\"type\":\"x\"}") +
        "{\"type\":\"queue-operation\",\"operation\":\"dequeue\",\"sessionId\":\"" + session +
        "\"}\n" + line("user", u1, "") + line("assistant", u2, u3) +
        "{\"type\":\"cost-state\",\"sessionId\":\"" + session + "\",\"totalCostUSD\":0}\n";
    summary = validate_claude_history(observed, binding());
    REQUIRE(summary && summary->entries == 7);
    const std::string shared_forward = line("attachment", u3, u1) + line("attachment", u4, u1) +
                                       line("user", u1, "") + line("assistant", u2, u3);
    summary = validate_claude_history(shared_forward, binding());
    REQUIRE(summary && summary->entries == 4);
    // Non-conversational records without identities are tolerated as opaque data.
    const std::string with_extras =
        "{\"type\":\"file-history-snapshot\",\"messageId\":\"x\",\"snapshot\":{"
        "\"trackedFileBackups\":{}}}\n" +
        history + "{\"type\":\"summary\",\"summary\":\"s\",\"leafUuid\":\"" + u2 + "\"}\n";
    summary = validate_claude_history(with_extras, binding());
    REQUIRE(summary && summary->entries == 4);
    auto validator = claude_history_validator(binding());
    REQUIRE(validator(history));
    return 0;
}

auto refused_history() -> int {
    const std::string good = line("user", u1, "") + line("assistant", u2, u1);
    REQUIRE(validate_claude_history(good, binding()));
    REQUIRE(!validate_claude_history(
        "{\"type\":\"user\",\"uuid\":\"" + u1 +
            "\",\"parentUuid\":null,\"version\":\"2.1.296\"}\n" + line("assistant", u2, u1),
        binding()
    ));
    REQUIRE(!validate_claude_history(
        line("user", u1, "") + "{\"type\":\"assistant\",\"uuid\":\"" + u2 + "\",\"parentUuid\":\"" +
            u1 + "\",\"sessionId\":\"" + session + "\"}\n",
        binding()
    ));
    REQUIRE(!validate_claude_history(
        "{\"type\":\"user\",\"uuid\":\"" + u1 + "\",\"parentUuid\":null,\"sessionId\":\"" +
            session + "\"}\n" + line("assistant", u2, u1),
        binding()
    ));
    REQUIRE(!validate_claude_history(
        "{\"type\":\"assistant\",\"uuid\":\"" + u2 + "\",\"parentUuid\":\"" + u1 +
            "\",\"version\":\"2.1.296\"}\n" + line("user", u1, ""),
        binding()
    ));
    // Missing: no bytes, no exchange, stopped initial prompt (user only).
    REQUIRE(!validate_claude_history("", binding()));
    REQUIRE(!validate_claude_history(line("user", u1, ""), binding()));
    REQUIRE(!validate_claude_history(line("assistant", u2, ""), binding()));
    // Corrupt: truncated last line, malformed JSON, non-object line, empty line.
    REQUIRE(!validate_claude_history(good.substr(0, good.size() - 1), binding()));
    REQUIRE(!validate_claude_history(good + "{\"type\":\n", binding()));
    REQUIRE(!validate_claude_history(good + "[]\n", binding()));
    REQUIRE(!validate_claude_history(good + "\n", binding()));
    REQUIRE(!validate_claude_history(good + "{\"type\":\"user\",\"type\":\"x\"}\n", binding()));
    // Aliased/duplicate identity and dangling parent.
    REQUIRE(!validate_claude_history(good + line("user", u1, u2), binding()));
    REQUIRE(!validate_claude_history(
        good + line("user", u3, "44444444-4444-4444-8444-444444444444"), binding()
    ));
    REQUIRE(!validate_claude_history(line("user", u1, u2) + line("assistant", u2, u1), binding()));
    REQUIRE(!validate_claude_history(
        line("user", "not-a-uuid", "") + line("assistant", u2, ""), binding()
    ));
    // Another conversation or an unqualified runtime version.
    auto other = binding();
    other.conversation_id = u3;
    REQUIRE(!validate_claude_history(good, other));
    auto future = binding();
    future.runtime_version = "2.1.299";
    REQUIRE(!validate_claude_history(good, future));
    REQUIRE(
        !validate_claude_history(good + "{\"type\":\"user\",\"version\":\"9.0.0\"}\n", binding())
    );
    // Missing or unbounded type.
    REQUIRE(!validate_claude_history(good + "{\"uuid\":\"" + u3 + "\"}\n", binding()));
    REQUIRE(!validate_claude_history(good + "{\"type\":\"bad type!\"}\n", binding()));
    REQUIRE(!validate_claude_history(good + "{\"type\":123}\n", binding()));
    // Depth bound.
    std::string deep = "{\"type\":\"user\",\"x\":";
    for (int index = 0; index < 70; ++index) {
        deep += "[";
    }
    for (int index = 0; index < 70; ++index) {
        deep += "]";
    }
    deep += "}\n";
    REQUIRE(!validate_claude_history(good + deep, binding()));
    // Invalid binding.
    REQUIRE(!validate_claude_history(good, {.conversation_id = "x", .runtime_version = "2.1.296"}));
    REQUIRE(!validate_claude_history(good, {.conversation_id = session, .runtime_version = ""}));
    return 0;
}

auto long_parent_chain() -> int {
    std::string history;
    std::size_t entries = 0;
    for (std::size_t index = 1; index < max_checkpoint_entries; ++index) {
        const auto uuid = chain_uuid(max_checkpoint_entries - index);
        const auto parent =
            index == 1 ? std::string{} : chain_uuid(max_checkpoint_entries - index + 1);
        const auto record = line(index == 1 ? "user" : "attachment", uuid, parent);
        const auto assistant = line("assistant", chain_uuid(0), uuid);
        if (history.size() + record.size() + assistant.size() > max_checkpoint_bytes) {
            break;
        }
        history += record;
        ++entries;
    }
    REQUIRE(entries > 0);
    history += line("assistant", chain_uuid(0), chain_uuid(max_checkpoint_entries - entries));
    const auto summary = validate_claude_history(history, binding());
    REQUIRE(summary && summary->entries == entries + 1);
    REQUIRE(
        entries + 1 == max_checkpoint_entries ||
        history.size() + 2 * max_checkpoint_line_bytes >= max_checkpoint_bytes
    );
    return 0;
}

auto project_leaf() -> int {
    auto leaf = claude_project_leaf("/Users/example/work-space_1");
    REQUIRE(leaf && *leaf == "-Users-example-work-space_1");
    REQUIRE(claude_project_leaf("/a/b.c") == "-a-b-c");
    REQUIRE(!claude_project_leaf("relative"));
    REQUIRE(!claude_project_leaf("/trailing/"));
    REQUIRE(!claude_project_leaf("/with space"));
    REQUIRE(!claude_project_leaf("/"));
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(shape_guard() == 0);
    REQUIRE(accepted_history() == 0);
    REQUIRE(refused_history() == 0);
    REQUIRE(long_parent_chain() == 0);
    REQUIRE(project_leaf() == 0);
    return 0;
}
