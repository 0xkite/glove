#include "pi_runtime_library_fixture.hpp"

#include <cstdio>

auto main() -> int {
    if (pi_runtime_library_value() != 42) {
        return 1;
    }
    return std::puts("snapshot-library-ok") < 0 ? 1 : 0;
}
