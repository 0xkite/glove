#pragma once

#include <fcntl.h>

#include <cerrno>

namespace glove::container::detail {

inline constexpr char stdio_admission_message[] = "stdio must be open before launch preparation";

// Admission must precede every internal open. Callers keep operator mappings
// stable during preparation; this does not claim cross-thread FD identity.
[[nodiscard]] inline auto stdio_admission_error() noexcept -> int {
    for (int descriptor = 0; descriptor != 3; ++descriptor) {
        int flags = -1;
        int error = EIO;
        for (int attempt = 0; attempt != 8; ++attempt) {
            flags = ::fcntl(descriptor, F_GETFD);
            if (flags >= 0) {
                break;
            }
            error = errno;
            if (error != EINTR) {
                break;
            }
        }
        if (flags < 0) {
            return error;
        }
    }
    return 0;
}

} // namespace glove::container::detail
