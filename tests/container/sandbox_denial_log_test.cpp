#include "sandbox_denial_log.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <expected>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s at %d\n", #condition, __LINE__);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

using glove::container::detail::classify_denial_operation;
using glove::container::detail::denial_class;
using glove::container::detail::denial_event;
using glove::container::detail::denial_parse_error;
using glove::container::detail::max_denial_line_bytes;
using glove::container::detail::parse_denial_line;

constexpr std::size_t max_seed_bytes = 65536;

std::string corpus_dir;

// Bounded read of one seed; a missing or oversized file is a test failure.
auto read_seed(std::string_view name) -> std::optional<std::string> {
    std::ifstream file{corpus_dir + "/" + std::string{name}, std::ios::binary};
    if (!file) {
        std::fprintf(stderr, "cannot open seed %.*s\n", static_cast<int>(name.size()), name.data());
        return std::nullopt;
    }
    std::string bytes(max_seed_bytes + 1, '\0');
    file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    const auto got = static_cast<std::size_t>(file.gcount());
    if (got > max_seed_bytes) {
        return std::nullopt;
    }
    bytes.resize(got);
    while (!bytes.empty() && (bytes.back() == '\n' || bytes.back() == '\r')) {
        bytes.pop_back();
    }
    return bytes;
}

auto parse_seed(std::string_view name)
    -> std::optional<std::expected<denial_event, denial_parse_error>> {
    auto bytes = read_seed(name);
    if (!bytes) {
        return std::nullopt;
    }
    return parse_denial_line(*bytes);
}

auto rejected_with(std::string_view name, denial_parse_error expected) -> bool {
    const auto parsed = parse_seed(name);
    return parsed && !parsed->has_value() && parsed->error() == expected;
}

auto valid_seeds() -> int {
    {
        const auto parsed = parse_seed("valid-mach-lookup.json");
        REQUIRE(parsed && parsed->has_value());
        const auto& event = **parsed;
        REQUIRE(event.readings.size() == 1);
        const auto& reading = event.readings[0];
        REQUIRE(reading.pid == 60708);
        REQUIRE(reading.code == 1);
        REQUIRE(reading.untrusted_comm == "mprobe");
        REQUIRE(reading.operation == "mach-lookup");
        REQUIRE(reading.kind == denial_class::mach);
        REQUIRE(reading.target == "glove.probe.plain");
        REQUIRE(!reading.target_truncated);
        REQUIRE(event.duplicate_reports == 0);
        REQUIRE(event.unix_micros == 1794978504776287);
        REQUIRE(event.mach_timestamp == 5484759082370U);
        REQUIRE(!event.ambiguous());
    }
    {
        const auto parsed = parse_seed("valid-file-read-spaces-quotes.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        const auto& reading = (*parsed)->readings[0];
        REQUIRE(reading.pid == 53833);
        REQUIRE(reading.kind == denial_class::file_read);
        REQUIRE(reading.target == "/private/tmp/glove-probe/a b/q\"uote\\back.txt");
    }
    {
        const auto parsed = parse_seed("valid-utf8-path.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        const auto& reading = (*parsed)->readings[0];
        REQUIRE(reading.kind == denial_class::file_read);
        REQUIRE(reading.target.ends_with("\xC3\xA9.txt"));
    }
    {
        const auto parsed = parse_seed("valid-file-write-create.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        const auto& reading = (*parsed)->readings[0];
        REQUIRE(reading.pid == 53752);
        REQUIRE(reading.kind == denial_class::file_write);
        REQUIRE(reading.untrusted_comm == "bash");
    }
    {
        const auto parsed = parse_seed("valid-syscall-unix-multiline.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        const auto& reading = (*parsed)->readings[0];
        REQUIRE(reading.pid == 1372);
        REQUIRE(reading.kind == denial_class::syscall);
        REQUIRE(reading.target == "186\nsyscall-unix-denied");
    }
    {
        const auto parsed = parse_seed("valid-duplicate-report-plural.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->duplicate_reports == 8);
        REQUIRE((*parsed)->readings.size() == 1);
        const auto& reading = (*parsed)->readings[0];
        REQUIRE(reading.pid == 1775);
        REQUIRE(reading.kind == denial_class::system_info);
        REQUIRE(reading.target == "vfs.disk-space");
    }
    {
        const auto parsed = parse_seed("valid-duplicate-report-singular.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->duplicate_reports == 1);
        REQUIRE((*parsed)->readings.size() == 1);
        REQUIRE((*parsed)->readings[0].pid == 53752);
        REQUIRE((*parsed)->readings[0].kind == denial_class::file_read);
    }
    {
        const auto parsed = parse_seed("valid-comm-32-bytes.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        REQUIRE((*parsed)->readings[0].pid == 65171);
        REQUIRE((*parsed)->readings[0].untrusted_comm.size() == 32);
    }
    {
        const auto parsed = parse_seed("valid-target-4096-truncates.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        REQUIRE((*parsed)->readings[0].target.size() == 4096);
        REQUIRE((*parsed)->readings[0].target_truncated);
    }
    return 0;
}

auto hostile_and_rejected_seeds() -> int {
    {
        const auto parsed = parse_seed("hostile-target-embedded-newline-forgery.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        REQUIRE((*parsed)->readings[0].pid == 60708);
        REQUIRE(
            (*parsed)->readings[0].target.find("Sandbox: gloved(1) deny(1)") != std::string::npos
        );
        for (const auto& reading : (*parsed)->readings) {
            REQUIRE(reading.pid != 1);
        }
    }
    {
        const auto parsed = parse_seed("hostile-target-control-bytes.json");
        REQUIRE(parsed && parsed->has_value());
        REQUIRE((*parsed)->readings.size() == 1);
        REQUIRE((*parsed)->readings[0].pid == 60708);
        REQUIRE((*parsed)->readings[0].target.find('\x1B') != std::string::npos);
    }
    {
        const auto parsed = parse_seed("hostile-comm-spoofs-second-denial.json");
        REQUIRE(parsed && parsed->has_value());
        const auto& event = **parsed;
        REQUIRE(event.readings.size() == 2);
        REQUIRE(event.ambiguous());
        REQUIRE(event.readings[0].pid == 1);
        REQUIRE(event.readings[0].operation == "file-read-data");
        REQUIRE(event.readings[0].untrusted_comm == "x");
        REQUIRE(event.readings[1].pid == 65172);
        REQUIRE(event.readings[1].operation == "mach-lookup");
        REQUIRE(event.readings[1].untrusted_comm == "x(1) deny(1) file-read-data y");
        REQUIRE(event.readings[1].target == "glove.b1.before");
    }
    REQUIRE(
        rejected_with("hostile-userland-forgery-logger.json", denial_parse_error::wrong_provenance)
    );
    REQUIRE(
        rejected_with("hostile-sender-suffix-lookalike.json", denial_parse_error::wrong_provenance)
    );
    {
        // Whether Glaze accepts raw non-UTF-8 bytes is unspecified; only the
        // bounds are asserted.
        const auto parsed = parse_seed("hostile-non-utf8-target.json");
        REQUIRE(parsed);
        if (parsed->has_value()) {
            REQUIRE((*parsed)->readings.size() == 1);
            REQUIRE((*parsed)->readings[0].pid == 60708);
            REQUIRE((*parsed)->readings[0].target.size() <= 4096);
            std::fprintf(stderr, "hostile-non-utf8-target.json: parsed\n");
        } else {
            std::fprintf(
                stderr,
                "hostile-non-utf8-target.json: error %d\n",
                static_cast<int>(parsed->error())
            );
        }
    }
    REQUIRE(rejected_with("reject-banner.txt", denial_parse_error::not_json));
    REQUIRE(rejected_with("reject-truncated-object.json", denial_parse_error::not_json));
    REQUIRE(rejected_with("reject-not-a-denial.json", denial_parse_error::not_a_denial));
    REQUIRE(rejected_with("reject-bad-timestamp.json", denial_parse_error::bad_timestamp));
    REQUIRE(rejected_with("reject-oversized-line.json", denial_parse_error::oversized));
    return 0;
}

// valid-mach-lookup.json with its message text replaced. Messages built here
// contain no byte that needs JSON escaping.
auto with_message(const std::string& base, std::string_view message) -> std::optional<std::string> {
    constexpr std::string_view original =
        "Sandbox: mprobe(60708) deny(1) mach-lookup glove.probe.plain";
    const auto at = base.find(original);
    if (at == std::string::npos) {
        return std::nullopt;
    }
    std::string line = base;
    line.replace(at, original.size(), message);
    return line;
}

auto message_cases() -> int {
    const auto base = read_seed("valid-mach-lookup.json");
    REQUIRE(base);
    const auto parse_message = [&](std::string_view message) {
        const auto line = with_message(*base, message);
        return line ? parse_denial_line(*line)
                    : std::expected<denial_event, denial_parse_error>{
                          std::unexpect, denial_parse_error::not_json
                      };
    };
    const auto rejected = [&](std::string_view message) {
        const auto parsed = parse_message(message);
        return !parsed && parsed.error() == denial_parse_error::not_a_denial;
    };

    REQUIRE(rejected("Sandbox: " + std::string(33, 'c') + "(5) deny(1) mach-lookup x"));
    REQUIRE(rejected("Sandbox: c(0) deny(1) mach-lookup x"));
    REQUIRE(rejected("Sandbox: c(1234567890) deny(1) mach-lookup x"));
    {
        const auto parsed = parse_message("Sandbox: c(5) deny(1) File-Read x");
        REQUIRE(parsed && parsed->readings.size() == 1);
        REQUIRE(parsed->readings[0].kind == denial_class::other);
    }
    REQUIRE(rejected("Sandbox: c(5) deny(1) " + std::string(65, 'o') + " x"));
    {
        const auto parsed = parse_message("Sandbox: x(1) deny(1) deny(1) deny(1) deny(1) op");
        REQUIRE(parsed && parsed->readings.size() == 4);
        constexpr std::array<std::string_view, 4> operations{"deny(1)", "deny(1)", "deny(1)", "op"};
        for (std::size_t index = 0; index != operations.size(); ++index) {
            REQUIRE(parsed->readings[index].pid == 1);
            REQUIRE(parsed->readings[index].operation == operations.at(index));
        }
    }
    {
        const auto parsed = parse_message("Sandbox: c(5) deny(1) mach-lookup");
        REQUIRE(parsed && parsed->readings.size() == 1);
        REQUIRE(parsed->readings[0].target.empty());
    }
    {
        const std::string head = "Sandbox: c(5) deny(1) mach-lookup ";
        const auto probe = with_message(*base, head);
        REQUIRE(probe && probe->size() < max_denial_line_bytes);
        const auto at_limit =
            with_message(*base, head + std::string(max_denial_line_bytes - probe->size(), 't'));
        REQUIRE(at_limit && at_limit->size() == max_denial_line_bytes);
        const auto accepted = parse_denial_line(*at_limit);
        REQUIRE(accepted || accepted.error() != denial_parse_error::oversized);
        const auto over = *at_limit + " ";
        const auto refused = parse_denial_line(over);
        REQUIRE(!refused && refused.error() == denial_parse_error::oversized);
    }
    return 0;
}

auto classifier_table() -> int {
    struct row {
        std::string_view operation;
        denial_class kind;
    };

    constexpr std::array rows{
        row{"file-read-data", denial_class::file_read},
        row{"file-read*", denial_class::file_read},
        row{"file-write-create", denial_class::file_write},
        row{"file-ioctl", denial_class::file_other},
        row{"network-outbound", denial_class::network},
        row{"mach-lookup", denial_class::mach},
        row{"ipc-posix-shm-read-data", denial_class::ipc},
        row{"process-info-pidinfo", denial_class::process_info},
        row{"process-fork", denial_class::process},
        row{"signal", denial_class::signal},
        row{"sysctl-read", denial_class::sysctl},
        row{"system-info", denial_class::system_info},
        row{"system-socket", denial_class::other},
        row{"iokit-open-service", denial_class::iokit},
        row{"syscall-unix", denial_class::syscall},
        row{"", denial_class::other},
        row{"FILE-READ", denial_class::other},
    };
    for (const auto& entry : rows) {
        REQUIRE(classify_denial_operation(entry.operation) == entry.kind);
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: container_sandbox_denial_log_test <corpus-dir>\n");
        return 2;
    }
    corpus_dir = argv[1];
    if (const int failed = valid_seeds(); failed != 0) {
        return failed;
    }
    if (const int failed = hostile_and_rejected_seeds(); failed != 0) {
        return failed;
    }
    if (const int failed = message_cases(); failed != 0) {
        return failed;
    }
    return classifier_table();
}
