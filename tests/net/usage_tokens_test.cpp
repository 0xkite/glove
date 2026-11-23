// Token counts are read from provider responses by field name, for whole
// JSON bodies and for server-sent event streams, and nothing is reported for
// bodies that do not carry them or cannot be read.

#include "usage_tokens.hpp"

#include <cstdio>
#include <string>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::net::detail::read_usage_tokens;

auto run() -> int {
    // OpenAI chat completions, one body.
    auto chat = read_usage_tokens(
        R"({"id":"x","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":34,"total_tokens":154}})"
    );
    REQUIRE(chat.reported && chat.input == 120 && chat.output == 34);

    // Anthropic messages, a stream: input in message_start, output growing in
    // message_delta. The largest of each wins.
    const std::string anthropic_stream =
        "event: message_start\n"
        "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":900,"
        "\"output_tokens\":1}}}\n\n"
        "event: content_block_delta\n"
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n"
        "event: message_delta\r\n"
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":57}}\r\n\r\n"
        "data: [DONE]\n";
    auto anthropic = read_usage_tokens(anthropic_stream);
    REQUIRE(anthropic.reported && anthropic.input == 900 && anthropic.output == 57);

    // OpenAI responses stream: usage nested inside the completed response.
    auto responses = read_usage_tokens(
        "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":11,"
        "\"output_tokens\":22}}}\n"
    );
    REQUIRE(responses.reported && responses.input == 11 && responses.output == 22);

    // Google generative AI names.
    auto google = read_usage_tokens(
        R"({"candidates":[],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3}})"
    );
    REQUIRE(google.reported && google.input == 7 && google.output == 3);

    // Nothing to report.
    for (const char* body :
         {"",
          "not json",
          "{\"choices\":[]}",
          "{\"usage\":\"none\"}",
          "data: {broken\n",
          "{\"usage\":{\"prompt_tokens\":\"12\"}}",
          "[1,2,3]"}) {
        const auto none = read_usage_tokens(body);
        REQUIRE(none.input == 0 && none.output == 0);
    }
    // A field present but not a usable count is reported as zero.
    auto negative =
        read_usage_tokens(R"({"usage":{"prompt_tokens":-5,"completion_tokens":1e300}})");
    REQUIRE(negative.input == 0 && negative.output == 0);

    // Deep nesting does not recurse without bound.
    std::string deep;
    for (int level = 0; level != 200; ++level) {
        deep += "{\"a\":";
    }
    deep += "{\"usage\":{\"prompt_tokens\":5}}";
    for (int level = 0; level != 200; ++level) {
        deep += "}";
    }
    const auto bounded = read_usage_tokens(deep);
    REQUIRE(bounded.input == 0);
    std::printf("usage tokens ok\n");
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
