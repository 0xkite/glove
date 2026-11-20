// `glove exec` on macOS records a short-lived child's sandbox denial between
// the launch and exit records, bounded and printable, without telling a
// non-terminal stderr anything when telemetry is live.

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>

#ifndef GLOVE_BIN
#    error "GLOVE_BIN must point at the glove executable"
#endif

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

constexpr int skip_code = 77;
constexpr int trials = 20;
constexpr std::size_t max_audit_lines = 300;

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

// The position of the first line at or after FROM that contains every needle,
// or npos.
auto line_with(
    const std::string& text, std::size_t from, std::initializer_list<std::string_view> needles
) -> std::size_t {
    std::size_t start = from;
    while (start < text.size()) {
        auto end = text.find('\n', start);
        if (end == std::string::npos) {
            end = text.size();
        }
        const std::string_view line{text.data() + start, end - start};
        if (std::ranges::all_of(needles, [&](std::string_view needle) {
                return line.contains(needle);
            })) {
            return start;
        }
        start = end + 1;
    }
    return std::string::npos;
}

auto trial(int number, const std::filesystem::path& home) -> int {
    std::error_code ec;
    const auto base =
        std::filesystem::temp_directory_path() /
        ("glove_exec_denial_" + std::to_string(::getpid()) + "_" + std::to_string(number));
    const auto workspace = base / "workspace";
    const auto audit = base / "audit.jsonl";
    const auto child_stderr = base / "stderr.txt";
    std::filesystem::create_directories(workspace, ec);
    REQUIRE(!ec);
    const std::string marker =
        ".glove_denial_e2e_" + std::to_string(::getpid()) + "_" + std::to_string(number);
    const auto forbidden = home / marker;
    const std::string script = "/usr/bin/touch '" + forbidden.string() + "'; exit 0";

    const ::pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        const int fd = ::open(child_stderr.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || ::dup2(fd, STDERR_FILENO) < 0) {
            std::_Exit(126);
        }
        ::close(fd);
        ::execl(
            GLOVE_BIN,
            GLOVE_BIN,
            "exec",
            "--workspace",
            workspace.c_str(),
            "--audit-log",
            audit.c_str(),
            "--",
            "/bin/sh",
            "-c",
            script.c_str(),
            static_cast<char*>(nullptr)
        );
        std::_Exit(127);
    }
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    if (std::filesystem::exists(forbidden, ec)) {
        std::filesystem::remove(forbidden, ec);
        std::fprintf(stderr, "sandbox did not hold: %s exists\n", forbidden.c_str());
        return 1;
    }
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);

    const std::string contents = read_file(audit);
    if (number == 1 && contents.contains(R"(\"state\":\"unavailable\")")) {
        std::printf("SKIP denial telemetry unavailable\n");
        std::filesystem::remove_all(base, ec);
        return skip_code;
    }
    const auto p1 = line_with(contents, 0, {R"("tool":"telemetry")", R"(\"state\":\"live\")"});
    REQUIRE(p1 != std::string::npos);
    const auto p2 = line_with(contents, p1 + 1, {R"("action":"agent_launch")"});
    REQUIRE(p2 != std::string::npos);
    const std::string comm = R"(\"comm\":\"touch\")";
    const auto p3 = line_with(
        contents, p2 + 1, {R"("action":"sandbox_denial")", R"("tool":"file_write")", marker, comm}
    );
    REQUIRE(p3 != std::string::npos);
    const auto p4 = line_with(contents, p3 + 1, {R"("tool":"summary")", R"(\"end_proof\":true)"});
    REQUIRE(p4 != std::string::npos);
    const auto p5 = line_with(contents, p4 + 1, {R"("action":"agent_exit")"});
    REQUIRE(p5 != std::string::npos);

    REQUIRE(!read_file(child_stderr).contains("denial telemetry"));
    REQUIRE(static_cast<std::size_t>(std::ranges::count(contents, '\n')) <= max_audit_lines);
    REQUIRE(std::ranges::all_of(contents, [](char byte) {
        const auto value = static_cast<unsigned char>(byte);
        return value == 0x0AU || (value >= 0x20U && value <= 0x7EU);
    }));
    std::printf("E trial %d ok\n", number);
    std::filesystem::remove_all(base, ec);
    return 0;
}

} // namespace

auto main() -> int {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    const char* home = std::getenv("HOME");
    REQUIRE(home != nullptr && *home == '/');
    for (int number = 1; number <= trials; ++number) {
        if (const int failed = trial(number, home); failed != 0) {
            return failed;
        }
    }
    std::printf("exec denial audit ok\n");
    return 0;
}
