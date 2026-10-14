#include "claude_history.hpp"
#include "json_shape.hpp"

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
    REQUIRE(project_leaf() == 0);
    return 0;
}
