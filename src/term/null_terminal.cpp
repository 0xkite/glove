#include "glove/term/terminal.hpp"

#include <cstdio>
#include <memory>
#include <mutex>
#include <string_view>

namespace glove::term {

// Internal factory hook consumed by factory.cpp; keep it out of the public
// terminal API while satisfying toolchains that require a prior declaration.
auto make_null_terminal() -> std::unique_ptr<terminal>;

namespace {

// Stdout-backed terminal. Used as the fallback when no frontend is enabled,
// and as a baseline for tests. Locked because callers may write from multiple
// threads.
class null_terminal final : public terminal {
public:
    void write(std::string_view text) override {
        std::scoped_lock lock(mu_);
        std::fwrite(text.data(), 1, text.size(), stdout);
    }

    void flush() override {
        std::scoped_lock lock(mu_);
        std::fflush(stdout);
    }

private:
    std::mutex mu_;
};

} // namespace

auto make_null_terminal() -> std::unique_ptr<terminal> {
    return std::make_unique<null_terminal>();
}

} // namespace glove::term
