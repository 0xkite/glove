#pragma once

// The default audit journal for one launch. Launches of one user share
// <state>/glove/logs/session.jsonl, and a journal has one writer for as long
// as its launch lives. A launch that finds the shared journal held by another
// live launch records to its own journal beside it, so concurrent launches
// never fail each other and never interleave their records.

#include "glove/audit/sink.hpp"

#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace glove::run::detail {

// Journals of finished concurrent launches kept beside the shared one. When a
// new one is created and more exist, the oldest that no live launch holds
// are removed. Each is bounded like the shared journal.
constexpr std::size_t max_overflow_audit_journals = 64;
constexpr std::size_t max_audit_directory_entries = 4096;

struct default_audit_journal {
    std::shared_ptr<glove::audit::sink> sink;
    std::filesystem::path path;
    // True when PATH is this launch's own journal because the shared one was
    // held by another live launch.
    bool overflow = false;
};

// What a launch prints on stderr, followed by the journal's path and a
// newline, when it records to its own journal. The text is stable so a
// harness can find the journal: the path is everything after the prefix.
inline constexpr std::string_view own_audit_journal_notice_prefix =
    "glove: another launch holds the default audit journal; this launch records to ";

// SHARED is the absolute path of the shared journal in a directory the caller
// has already validated and made owner-only. Any error but a held lock is
// returned as it is: an unsafe journal is never worked around.
[[nodiscard]] auto open_default_audit_journal(
    const std::filesystem::path& shared, glove::audit::jsonl_sink_limits limits
) -> std::expected<default_audit_journal, std::string>;

// "session.<16 lowercase hex>.jsonl" for the shared journal "session.jsonl".
[[nodiscard]] auto is_overflow_audit_journal_name(
    std::string_view name, std::string_view shared_stem, std::string_view shared_extension
) -> bool;

} // namespace glove::run::detail
