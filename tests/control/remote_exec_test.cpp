#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

[[nodiscard]] auto run_executor(const std::vector<std::string>& arguments) -> int {
    const auto child = ::fork();
    if (child < 0) {
        return -1;
    }
    if (child == 0) {
        const int null_descriptor = ::open("/dev/null", O_WRONLY);
        if (null_descriptor >= 0) {
            (void)::dup2(null_descriptor, STDERR_FILENO);
            (void)::close(null_descriptor);
        }
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 2U);
        argv.push_back(const_cast<char*>(GLOVE_REMOTE_EXEC_BIN));
        for (const auto& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        ::execv(GLOVE_REMOTE_EXEC_BIN, argv.data());
        _exit(127);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

auto run() -> int {
    REQUIRE(run_executor({}) == 2);
    REQUIRE(run_executor({"--stdio", "unexpected"}) == 2);
    REQUIRE(run_executor({"--help"}) == 2);
    REQUIRE(run_executor({"--local-validation-stdio", "relative-config"}) == 2);
    REQUIRE(run_executor({"--local-validation-stdio", "/definitely/missing/config"}) == 1);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
