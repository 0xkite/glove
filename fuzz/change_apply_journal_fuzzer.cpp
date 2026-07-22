#include "glove/supervisor/change_apply_journal.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>

namespace {

constexpr std::size_t maximum_journal_bytes = 64U * 1024U;

class temporary_journal_file {
public:
    temporary_journal_file() {
        constexpr char directory_template[] = "/tmp/glove-change-apply-fuzzer-XXXXXX";
        std::array<char, sizeof(directory_template)> directory_buffer{};
        std::copy_n(directory_template, directory_buffer.size(), directory_buffer.begin());
        const char* const created_directory = ::mkdtemp(directory_buffer.data());
        if (created_directory == nullptr) {
            std::abort();
        }
        directory_ = created_directory;
        path_ = directory_ + "/journal";
        descriptor_ =
            ::open(path_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (descriptor_ < 0 || ::fchmod(descriptor_, 0600) != 0) {
            std::abort();
        }
    }

    temporary_journal_file(const temporary_journal_file&) = delete;
    auto operator=(const temporary_journal_file&) -> temporary_journal_file& = delete;

    ~temporary_journal_file() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
        if (!path_.empty()) {
            (void)::unlink(path_.c_str());
        }
        if (!directory_.empty()) {
            (void)::rmdir(directory_.c_str());
        }
    }

    [[nodiscard]] auto overwrite(const std::uint8_t* data, std::size_t size) const -> bool {
        if (size > static_cast<std::size_t>(std::numeric_limits<off_t>::max()) ||
            ::ftruncate(descriptor_, 0) != 0) {
            return false;
        }
        std::size_t written = 0;
        while (written < size) {
            const auto result =
                ::pwrite(descriptor_, data + written, size - written, static_cast<off_t>(written));
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                return false;
            }
            written += static_cast<std::size_t>(result);
        }
        return true;
    }

    [[nodiscard]] auto path() const -> const std::string& { return path_; }

private:
    int descriptor_ = -1;
    std::string directory_;
    std::string path_;
};

auto journal_file() -> temporary_journal_file& {
    static temporary_journal_file file;
    return file;
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    if (size > maximum_journal_bytes) {
        return 0;
    }

    auto& file = journal_file();
    if (!file.overwrite(data, size)) {
        std::abort();
    }
    // Exercise the descriptor-validated production recovery path, including
    // untrusted header and newline-framed record bytes.
    static_cast<void>(
        glove::supervisor::change_apply_journal::open(file.path(), maximum_journal_bytes)
    );
    return 0;
}
