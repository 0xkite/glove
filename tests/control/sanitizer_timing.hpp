#ifndef GLOVE_TESTS_CONTROL_SANITIZER_TIMING_HPP
#define GLOVE_TESTS_CONTROL_SANITIZER_TIMING_HPP

#include <cstdint>

// ThreadSanitizer instrumentation slows execution by roughly an order of
// magnitude. Tests that assert short wall-clock deadlines or configure short
// IO timeouts are correct under normal and AddressSanitizer builds, but under
// TSan those deadlines are exceeded on legitimate work, producing false
// timeouts rather than real findings. Multiply such timing values by this
// factor so the deadlines reflect the time actually available. Race detection
// is unaffected: only the timeouts grow, never the exercised code paths.
namespace glove_test {

#if defined(__has_feature)
#    if __has_feature(thread_sanitizer)
#        define GLOVE_TEST_THREAD_SANITIZER 1
#    endif
#endif
#if !defined(GLOVE_TEST_THREAD_SANITIZER) && defined(__SANITIZE_THREAD__)
#    define GLOVE_TEST_THREAD_SANITIZER 1
#endif

#if defined(GLOVE_TEST_THREAD_SANITIZER)
inline constexpr std::int64_t timeout_scale = 10;
#else
inline constexpr std::int64_t timeout_scale = 1;
#endif

} // namespace glove_test

#endif // GLOVE_TESTS_CONTROL_SANITIZER_TIMING_HPP
