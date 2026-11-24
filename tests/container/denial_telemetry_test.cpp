// A sandbox denial rendered for the audit log: bounded, printable ASCII, no
// quote or backslash, and no agent text for an ambiguous line.

#include "glove/container/denial_telemetry.hpp"

#include "denial_telemetry_detail.hpp"
#include "sandbox_denial_log.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <string>
#include <string_view>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::container::encode_untrusted;
using glove::container::is_encoded_text;
using glove::container::detail::denial_class;
using glove::container::detail::denial_event;
using glove::container::detail::denial_kind_name;
using glove::container::detail::denial_reading;
using glove::container::detail::to_sandbox_denial;

auto encoder_cases() -> int {
    const auto plain = encode_untrusted("a b/c.txt", 512);
    REQUIRE(plain.text == "a b/c.txt" && !plain.truncated);

    const auto hostile = encode_untrusted("q\"b\\p%\n\x01\x7f\xff\xc3\xa9", 512);
    REQUIRE(hostile.text == "q%22b%5Cp%25%0A%01%7F%FF%C3%A9");
    REQUIRE(!hostile.truncated);

    const std::string with_nul{"a\0b", 3};
    REQUIRE(encode_untrusted(with_nul, 512).text == "a%00b");

    const auto long_plain = encode_untrusted(std::string(600, 'a'), 512);
    REQUIRE(long_plain.text == std::string(512, 'a') && long_plain.truncated);

    const auto newlines = encode_untrusted(std::string(200, '\n'), 512);
    REQUIRE(newlines.text.size() == 510 && newlines.truncated);

    const auto zero = encode_untrusted("ab", 0);
    REQUIRE(zero.text.empty() && zero.truncated);
    const auto empty = encode_untrusted("", 0);
    REQUIRE(empty.text.empty() && !empty.truncated);

    for (int value = 0; value <= 255; ++value) {
        const char byte = static_cast<char>(value);
        REQUIRE(is_encoded_text(encode_untrusted(std::string_view{&byte, 1}, 8).text));
    }
    return 0;
}

auto conversion_cases() -> int {
    denial_event one;
    one.readings.push_back(
        denial_reading{
            .pid = 42,
            .code = 1,
            .untrusted_comm = "to\"uch",
            .operation = "file-write-create",
            .kind = denial_class::file_write,
            .target = "/tmp/x\ny",
            .target_truncated = false,
        }
    );
    const auto single = to_sandbox_denial(one);
    REQUIRE(single.kind == "file_write");
    REQUIRE(single.operation == "file-write-create");
    REQUIRE(single.target == "/tmp/x%0Ay");
    REQUIRE(single.comm == "to%22uch");
    REQUIRE(single.pid == 42 && single.readings == 1 && !single.target_truncated);

    denial_event two = one;
    two.readings.push_back(one.readings.front());
    const auto ambiguous = to_sandbox_denial(two);
    REQUIRE(ambiguous.kind == "ambiguous");
    REQUIRE(ambiguous.operation.empty() && ambiguous.target.empty() && ambiguous.comm.empty());
    REQUIRE(ambiguous.pid == 0 && ambiguous.readings == 2);

    denial_event big = one;
    big.readings.front().target = std::string(4096, 'x');
    const auto bounded = to_sandbox_denial(big);
    REQUIRE(bounded.target.size() == 512 && bounded.target_truncated);

    constexpr std::array<std::pair<denial_class, std::string_view>, 14> names{{
        {denial_class::file_read, "file_read"},
        {denial_class::file_write, "file_write"},
        {denial_class::file_other, "file_other"},
        {denial_class::network, "network"},
        {denial_class::mach, "mach"},
        {denial_class::ipc, "ipc"},
        {denial_class::process_info, "process_info"},
        {denial_class::process, "process"},
        {denial_class::signal, "signal"},
        {denial_class::sysctl, "sysctl"},
        {denial_class::system_info, "system_info"},
        {denial_class::iokit, "iokit"},
        {denial_class::syscall, "syscall"},
        {denial_class::other, "other"},
    }};
    for (const auto& [kind, name] : names) {
        REQUIRE(denial_kind_name(kind) == name);
    }

    const auto escaped =
        glove::container::make_escape_denial("seccomp_user_notif", "ioctl(TIOCSTI)\n", 777);
    REQUIRE(escaped.kind == "syscall");
    REQUIRE(escaped.operation == "seccomp_user_notif");
    REQUIRE(escaped.target == "ioctl(TIOCSTI)%0A");
    REQUIRE(!escaped.target_truncated);
    REQUIRE(escaped.pid == 777 && escaped.readings == 1);

    const auto neg_pid = glove::container::make_escape_denial("seccomp", std::string(700, 'z'), -5);
    REQUIRE(neg_pid.pid == 0 && neg_pid.target.size() == 512 && neg_pid.target_truncated);
    return 0;
}

} // namespace

int main() {
    if (const int failed = encoder_cases(); failed != 0) {
        return failed;
    }
    if (const int failed = conversion_cases(); failed != 0) {
        return failed;
    }
    std::printf("denial telemetry ok\n");
    return 0;
}
