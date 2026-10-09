#include "pi_audit.hpp"

#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
thread_local bool reject_allocations = false;
}

// Test-only ABI allocation interception, not raw application ownership. This
// isolated binary rejects C++ allocations on its one test thread; malloc/free
// remain sanitizer-instrumented. No limits, suppressions or host services change.
auto operator new(std::size_t size) -> void* {
    if (reject_allocations) {
        throw std::bad_alloc{};
    }
    if (auto* memory = std::malloc(size == 0 ? 1 : size)) {
        return memory;
    }
    throw std::bad_alloc{};
}

auto operator new[](std::size_t size) -> void* {
    return ::operator new(size);
}

void operator delete(void* memory) noexcept {
    std::free(memory);
}

void operator delete[](void* memory) noexcept {
    std::free(memory);
}

void operator delete(void* memory, std::size_t) noexcept {
    std::free(memory);
}

void operator delete[](void* memory, std::size_t) noexcept {
    std::free(memory);
}

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class allocation_failure {
public:
    allocation_failure() noexcept : saved_{reject_allocations} { reject_allocations = true; }

    allocation_failure(const allocation_failure&) = delete;
    auto operator=(const allocation_failure&) -> allocation_failure& = delete;

    ~allocation_failure() { reject_allocations = saved_; }

private:
    bool saved_;
};

auto run() -> int {
    using glove::run::detail::make_pi_audit_sink;
    auto capacity = make_pi_audit_sink(1);
    constexpr auto populated_charge = sizeof(glove::audit::event) + 256U;
    auto copy = make_pi_audit_sink(2, populated_charge);
    REQUIRE(capacity && copy);
    const glove::audit::event empty{};
    glove::audit::event populated{};
    populated.tool_name.assign(256U, 'x');
    REQUIRE((*capacity)->record(empty));
    bool capacity_threw = false;
    bool factory_threw = false;
    bool invalid_threw = false;
    bool copy_threw = false;
    std::expected<void, std::string> capacity_result{};
    std::expected<void, std::string> copy_result{};
    std::expected<std::shared_ptr<glove::audit::sink>, std::string> factory_result{
        std::shared_ptr<glove::audit::sink>{}
    };
    auto invalid_result = factory_result;
    {
        allocation_failure fault;
        try {
            capacity_result = (*capacity)->record(empty);
        } catch (const std::bad_alloc&) {
            capacity_threw = true;
        }
        try {
            copy_result = (*copy)->record(populated);
        } catch (const std::bad_alloc&) {
            copy_threw = true;
        }
        try {
            factory_result = make_pi_audit_sink();
        } catch (const std::bad_alloc&) {
            factory_threw = true;
        }
        try {
            invalid_result = make_pi_audit_sink(0);
        } catch (const std::bad_alloc&) {
            invalid_threw = true;
        }
    }
    REQUIRE(!reject_allocations);
    // A failed append must leave the exact one-event byte allowance untouched.
    REQUIRE((*copy)->record(populated));
    auto exhausted = (*copy)->record(empty);
    REQUIRE(!exhausted && exhausted.error() == "Pi audit capacity reached");
    std::fprintf(
        stderr,
        "allocation failure escapes: capacity=%d copy=%d factory=%d invalid=%d\n",
        capacity_threw,
        copy_threw,
        factory_threw,
        invalid_threw
    );
    REQUIRE(!capacity_threw && !copy_threw && !factory_threw && !invalid_threw);
    REQUIRE(!capacity_result && !copy_result && !factory_result && !invalid_result);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
