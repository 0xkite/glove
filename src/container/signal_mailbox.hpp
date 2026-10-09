#pragma once

#include <atomic>
#include <cstdint>
#include <limits>

namespace glove::container::detail {

// A captured token binds a handler publication to one broker invocation.
// Session owners serialize arm/disarm; handlers publish through lock-free CAS.
class signal_mailbox {
public:
    using token = std::uint64_t;
    static constexpr token signal_bits = 0x0f;
    static constexpr token armed_bit = 0x10;
    static constexpr token generation_step = 0x100;
    static_assert(std::atomic<token>::is_always_lock_free);

    auto arm() noexcept -> bool {
        const auto generation = state_.load(std::memory_order_acquire) & ~token{0xff};
        if (generation == (std::numeric_limits<token>::max() & ~token{0xff})) {
            return false; // Never wrap a token into a previously used identity.
        }
        state_.store(generation + generation_step + armed_bit, std::memory_order_release);
        return true;
    }

    auto disarm() noexcept -> void {
        state_.fetch_and(~(armed_bit | signal_bits), std::memory_order_acq_rel);
    }

    auto capture() const noexcept -> token {
        const auto state = state_.load(std::memory_order_acquire);
        return (state & armed_bit) != 0 ? state & ~signal_bits : 0;
    }

    auto publish(token captured, token bit) noexcept -> bool {
        if (captured == 0 || bit == 0 || (bit & ~signal_bits) != 0) {
            return false;
        }
        auto current = state_.load(std::memory_order_acquire);
        while ((current & ~signal_bits) == captured) {
            if (state_.compare_exchange_weak(
                    current, current | bit, std::memory_order_acq_rel, std::memory_order_acquire
                )) {
                return true;
            }
        }
        return false;
    }

    auto take() noexcept -> token {
        return state_.fetch_and(~signal_bits, std::memory_order_acq_rel) & signal_bits;
    }

private:
    std::atomic<token> state_{0};
};

} // namespace glove::container::detail
