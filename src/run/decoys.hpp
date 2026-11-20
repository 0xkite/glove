#pragma once

// Decoys: canary files glove plants on the host for one launch, at paths a
// launch profile names, where no legitimate agent work should look. The
// sandbox cannot reach them (a decoy inside a grant is refused), so on macOS
// any attempt shows up as a sandbox denial whose target is a decoy, which the
// denial audit records separately as a high-confidence signal. Elsewhere a
// decoy is still a canary: its content is a random glvc_ token that appears
// nowhere else.
//
// The sandbox cannot list a decoy's directory, so a sandboxed process is
// seen only when it opens a decoy by its exact name. Realistic fixed names
// (a credential file the user does not have) catch real probing; a
// "{nonce}" name is seen only by a process told the name, which suits
// scripted scenarios. A fixed name that another live launch already planted
// is shared: watched here, owned by that launch.
//
// Identity is content, never a PID: glove removes a file only when it is a
// regular single-link file owned by the user whose bytes are exactly the
// canary it wrote. Each launch journals its decoys under the state
// directory before creating them and holds an exclusive lock on the journal
// while it runs; a later launch that can take the lock removes what a
// crashed launch left behind.

#include <cstddef>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

inline constexpr std::size_t max_decoys = 32;
inline constexpr std::string_view decoy_nonce_placeholder = "{nonce}";

class decoy_set {
public:
    // Plants one file per absolute path template, replacing {nonce} with a
    // fresh per-launch value. All or nothing: on any refusal the decoys
    // already planted are removed. Refuses a decoy inside or containing an
    // EXPOSED grant, one whose parent is missing, not a directory owned by
    // the user, or writable by group or others, and one where a file exists
    // that is not another live launch's decoy.
    [[nodiscard]] static auto plant(
        std::span<const std::string> templates,
        std::span<const std::string> exposed,
        const std::filesystem::path& journal_directory
    ) -> std::expected<decoy_set, std::string>;

    decoy_set() = default;
    decoy_set(const decoy_set&) = delete;
    auto operator=(const decoy_set&) -> decoy_set& = delete;
    decoy_set(decoy_set&& other) noexcept;
    auto operator=(decoy_set&& other) noexcept -> decoy_set&;
    ~decoy_set();

    // Paths as planted, in template order.
    [[nodiscard]] auto paths() const -> const std::vector<std::filesystem::path>& { return paths_; }

    // Removes every decoy that is still ours, then the journal. Idempotent.
    void remove() noexcept;

private:
    std::vector<std::filesystem::path> paths_;
    std::vector<std::string> canaries_;
    std::filesystem::path journal_;
    int journal_fd_ = -1;
};

// Removes decoys journaled by launches that no longer hold their journal
// lock. Best effort; returns how many decoy files it removed.
auto sweep_stale_decoys(const std::filesystem::path& journal_directory) noexcept -> std::size_t;

// <XDG_STATE_HOME>/glove/decoys, created owner-only.
[[nodiscard]] auto decoy_journal_directory() -> std::expected<std::filesystem::path, std::string>;

} // namespace glove::run::detail
