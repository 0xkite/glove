#include "glove/host/daemon.hpp"
#include "glove/host/setup.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

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
        std::string pattern = "/tmp/glove-daemon-test-XXXXXX";
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;
    temporary_directory(temporary_directory&&) = delete;
    auto operator=(temporary_directory&&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_{};
};

auto write_executable(const std::filesystem::path& path) -> bool {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output << "#!/bin/sh\nexit 0\n";
    output.close();
    return output.good() && ::chmod(path.c_str(), 0700) == 0;
}

auto run() -> int {
    using namespace glove::host;

    const temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const environment values{.home = temporary.root().string()};
    auto setup = plan_setup(setup_options{}, values);
    REQUIRE(setup.has_value());
    REQUIRE(execute_setup(*setup).has_value());

    const auto gloved = temporary.root() / "gloved test";
    REQUIRE(write_executable(gloved));
    auto plan = plan_daemon_service(
        daemon_options{.config_path = setup->config_path, .gloved_path = gloved}, values
    );
    REQUIRE(plan.has_value());
    REQUIRE(plan->config_path == setup->config_path);
    REQUIRE(plan->gloved_path == std::filesystem::canonical(gloved));
    REQUIRE(plan->service_definition.find(gloved.string()) != std::string::npos);
    REQUIRE(plan->service_definition.find(setup->config_path.string()) != std::string::npos);

#if defined(__linux__)
    REQUIRE(plan->manager == daemon_service_manager::systemd_user);
    REQUIRE(plan->service_name == "sage-gloved.service");
    REQUIRE(plan->service_path == temporary.root() / ".config/systemd/user/sage-gloved.service");
    REQUIRE(plan->service_definition.find("ExecStart=\"") != std::string::npos);
#elif defined(__APPLE__)
    REQUIRE(plan->manager == daemon_service_manager::launchd_user);
    REQUIRE(plan->service_name == "org.sage-protocol.gloved");
    REQUIRE(
        plan->service_path ==
        temporary.root() / "Library/LaunchAgents/org.sage-protocol.gloved.plist"
    );
    REQUIRE(plan->service_definition.find("<key>ProgramArguments</key>") != std::string::npos);
#endif
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
