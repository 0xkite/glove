#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <thread>
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

auto write_owner_file(const std::filesystem::path& path, std::string_view contents, mode_t mode)
    -> bool {
    std::ofstream output{path};
    output << contents;
    output.close();
    return output.good() && ::chmod(path.c_str(), mode) == 0;
}

auto run_glove(
    const std::filesystem::path& glove_bin,
    const std::filesystem::path& home,
    std::vector<std::string> argv_owned,
    const std::filesystem::path& stdout_path = {},
    std::chrono::milliseconds timeout = std::chrono::seconds{10}
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
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        const auto waited = ::waitpid(child, &status, WNOHANG);
        if (waited == child) {
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        if (waited < 0 && errno != EINTR) {
            return -1;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            (void)::kill(child, SIGKILL);
            while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            return -2;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
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

    // A project-controlled path can mimic Homebrew's Cellar layout and place
    // an arbitrary executable at the derived <prefix>/bin/brew path. Planning
    // must fail closed from filesystem metadata alone: it must neither execute
    // that binary nor wait for it, and it must not perform advertised writes.
    const auto fake_prefix = temporary.root() / "fake-homebrew";
    const auto fake_cellar_bin = fake_prefix / "Cellar" / "node" / "1.0" / "bin";
    const auto fake_harness_bin = temporary.root() / "fake-harness-bin";
    const auto marker = temporary.root() / "fake-brew-executed";
    const auto protected_file = temporary.root() / "must-not-change";
    REQUIRE(std::filesystem::create_directories(fake_cellar_bin));
    REQUIRE(std::filesystem::create_directories(fake_prefix / "bin"));
    REQUIRE(std::filesystem::create_directory(fake_harness_bin));
    REQUIRE(write_owner_file(protected_file, "unchanged\n", 0600));
    const auto fake_node = fake_cellar_bin / "node";
    REQUIRE(write_owner_file(fake_node, "#!/bin/sh\nexit 0\n", 0700));
    REQUIRE(write_owner_file(
        fake_prefix / "bin" / "brew",
        "#!/bin/sh\nprintf executed > '" + marker.string() + "'\nprintf changed > '" +
            protected_file.string() + "'\nsleep 10\n",
        0700
    ));
    REQUIRE(
        write_owner_file(fake_harness_bin / "codex", "#!" + fake_node.string() + "\nexit 0\n", 0700)
    );
    const auto adversarial_output = temporary.root() / "adversarial-plan.json";
    const int adversarial_status = run_glove(
        glove_bin,
        temporary.root(),
        {glove_bin,
         "setup",
         "plan",
         "--path-root",
         project.string(),
         "--search-path",
         fake_harness_bin.string(),
         "--runtime",
         "codex",
         "--json"},
        adversarial_output,
        std::chrono::seconds{2}
    );
    REQUIRE(!std::filesystem::exists(marker));
    {
        std::ifstream protected_input{protected_file};
        const std::string protected_contents{
            std::istreambuf_iterator<char>{protected_input},
            std::istreambuf_iterator<char>{},
        };
        REQUIRE(protected_contents == "unchanged\n");
    }
    REQUIRE(adversarial_status == 1);
    REQUIRE(!std::filesystem::exists(temporary.root() / ".config/glove/config.json"));
    REQUIRE(!std::filesystem::exists(temporary.root() / ".config/glove/session-policy.json"));
    REQUIRE(!std::filesystem::exists(temporary.root() / ".config/glove/harnesses"));

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
