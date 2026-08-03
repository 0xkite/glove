#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-onboarding-cli-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto run_glove(
    const std::filesystem::path& glove_bin,
    const std::filesystem::path& home,
    std::vector<std::string> argv_owned,
    const std::filesystem::path& stdout_path = {}
) -> int {
    std::vector<char*> argv;
    argv.reserve(argv_owned.size() + 1U);
    for (auto& argument : argv_owned) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    const auto child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        if (::setenv("HOME", home.c_str(), 1) != 0) {
            std::_Exit(127);
        }
        if (!stdout_path.empty()) {
            if (std::freopen(stdout_path.c_str(), "w", stdout) == nullptr) {
                std::_Exit(127);
            }
        }
        ::execv(glove_bin.c_str(), argv.data());
        std::_Exit(127);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) {
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

auto run() -> int {
    const char* glove_bin_value = std::getenv("GLOVE_BIN");
    REQUIRE(glove_bin_value != nullptr && glove_bin_value[0] != '\0');
    const std::string glove_bin{glove_bin_value};

    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto project = temporary.root() / "project";
    const auto harness_bin = temporary.root() / "harness-bin";
    const auto output = temporary.root() / "plan.json";
    REQUIRE(std::filesystem::create_directory(project));
    REQUIRE(std::filesystem::create_directory(harness_bin));
    {
        std::ofstream harness{harness_bin / "codex"};
        harness << "#!/bin/sh\nexit 0\n";
        REQUIRE(harness.good());
    }
    REQUIRE(::chmod((harness_bin / "codex").c_str(), 0700) == 0);
    REQUIRE(::chmod(harness_bin.c_str(), 0700) == 0);

    const std::vector<std::string> plan_argv{
        glove_bin,
        "setup",
        "plan",
        "--path-root",
        project.string(),
        "--search-path",
        harness_bin.string(),
        "--runtime",
        "codex",
        "--json",
    };
    REQUIRE(run_glove(glove_bin, temporary.root(), plan_argv, output) == 0);
    std::ifstream report{output};
    const std::string json{
        std::istreambuf_iterator<char>{report},
        std::istreambuf_iterator<char>{},
    };
    REQUIRE(json.find(R"("mode":"read_only")") != std::string::npos);
    REQUIRE(json.find(R"("session_policy_json")") == std::string::npos);
    REQUIRE(json.find(R"("network_denied":true)") != std::string::npos);
    REQUIRE(json.find(R"("credentials_configured":false)") != std::string::npos);
    REQUIRE(!std::filesystem::exists(temporary.root() / ".config/glove/config.json"));

    auto show_policy_argv = plan_argv;
    show_policy_argv.insert(show_policy_argv.end() - 1, "--show-policy");
    const auto full_output = temporary.root() / "full-plan.json";
    REQUIRE(run_glove(glove_bin, temporary.root(), std::move(show_policy_argv), full_output) == 0);
    std::ifstream full_report{full_output};
    const std::string full_json{
        std::istreambuf_iterator<char>{full_report},
        std::istreambuf_iterator<char>{},
    };
    REQUIRE(full_json.find(R"("session_policy_json":")") != std::string::npos);

    REQUIRE(
        run_glove(
            glove_bin,
            temporary.root(),
            {glove_bin,
             "setup",
             "plan",
             "--path-root",
             project.string(),
             "--search-path",
             harness_bin.string(),
             "--runtime",
             "pi",
             "--pi-settings",
             (temporary.root() / "pi-settings.json").string()}
        ) == 1
    );
    REQUIRE(
        run_glove(
            glove_bin, temporary.root(), {glove_bin, "setup", "plan", "--backend", "unsupported"}
        ) == 1
    );
    REQUIRE(run_glove(glove_bin, temporary.root(), {glove_bin, "setup", "plan", "--help"}) == 0);
    REQUIRE(run_glove(glove_bin, temporary.root(), {glove_bin, "setup", "plan", "--unknown"}) == 2);

    return 0;
}

} // namespace

int main() {
    return run();
}
