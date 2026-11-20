// glove-denial-replay: offline tooling for denial deciders. Not installed.
//
//   glove-denial-replay schema
//       The feature schema as JSON: {"feature_schema":<n>,"features":[...]}.
//
//   glove-denial-replay rows <manifest>
//       One JSON line per decision point (after each recorded denial) of
//       every listed trace: session, split, label, time and the feature
//       vector. The trainer reads these, so the feature schema has exactly
//       one implementation (denial_feature_builder).
//
//   glove-denial-replay evaluate <manifest> [--model <file>] [--split <name>]...
//       Replays the listed traces through the heuristic arm and, when given,
//       the model arm, and prints one JSON report: session-level confusion
//       counts at the flag and terminate levels, detection latency from the
//       labeled onset, and decision cost. Default splits: test and real.
//
// The manifest is JSON lines:
//   {"trace":"<path>","label":"benign"|"misbehaving","onset_ms":<n>,"split":"<name>"}
// A relative trace path is relative to the manifest's directory. onset_ms is
// when a misbehaving session starts misbehaving; decision points before it
// are labeled benign. Every input file is untrusted and bounded.

#include "glove/container/denial_decision.hpp"
#include "glove/container/denial_trace.hpp"

#include <glaze/glaze.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace glove::tools::denial_replay {

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct manifest_line {
    std::string trace;
    std::string label;
    std::int64_t onset_ms = 0;
    std::string split;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct row {
    std::size_t session = 0;
    std::string split;
    int label = 0;
    std::int64_t t_ms = 0;
    std::vector<float> features;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct confusion {
    std::uint64_t true_positive = 0;
    std::uint64_t false_positive = 0;
    std::uint64_t true_negative = 0;
    std::uint64_t false_negative = 0;
    // Misbehaving sessions whose first verdict at this level came before the
    // labeled onset: a fire on benign behaviour, counted inside true_positive.
    std::uint64_t before_onset = 0;
    double precision = 0.0;
    double recall = 0.0;
    double false_positive_rate = 0.0;
    std::int64_t latency_ms_p50 = -1;
    std::int64_t latency_ms_p90 = -1;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct arm_report {
    std::string arm;
    confusion flag;
    confusion terminate;
    double decide_ns_mean = 0.0;
    double decide_ns_p50 = 0.0;
    double decide_ns_p99 = 0.0;
};

// NOLINTNEXTLINE(misc-use-internal-linkage): Glaze reflection needs linkage.
struct evaluation {
    std::uint32_t feature_schema = container::denial_feature_schema_version;
    // Timings are comparable only from an optimized, unsanitized build.
    std::string timing_build;
    std::vector<std::string> splits;
    std::uint64_t sessions = 0;
    std::uint64_t misbehaving = 0;
    std::uint64_t decision_points = 0;
    double features_ns_mean = 0.0;
    std::vector<arm_report> arms;
};

} // namespace glove::tools::denial_replay

namespace {

namespace replay = glove::tools::denial_replay;
namespace container = glove::container;
using clock_type = std::chrono::steady_clock;

constexpr std::size_t max_manifest_bytes = std::size_t{4} << 20U;
constexpr std::size_t max_manifest_sessions = 100000;
constexpr std::size_t max_timing_samples = 1U << 20U;
constexpr std::size_t max_model_bytes = container::max_denial_model_bytes;

#if defined(__has_feature)
#    if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#        define GLOVE_REPLAY_SANITIZED 1
#    endif
#endif

constexpr auto timing_build() -> std::string_view {
#if defined(GLOVE_REPLAY_SANITIZED)
    return "sanitized";
#elif defined(NDEBUG)
    return "optimized";
#else
    return "debug";
#endif
}

struct line_opts : glz::opts {
    bool validate_trailing_whitespace = true;
};

constexpr line_opts strict_line{
    {.null_terminated = false, .error_on_unknown_keys = true, .error_on_missing_keys = true},
};

// Diagnostics go to stderr with the tool's prefix; a failed write to stderr
// has nowhere to be reported.
void write_stderr(std::string_view prefix, std::string_view text) noexcept {
    static_cast<void>(std::fwrite(prefix.data(), 1, prefix.size(), stderr));
    static_cast<void>(std::fwrite(text.data(), 1, text.size(), stderr));
    static_cast<void>(std::fputc('\n', stderr));
}

void complain(std::string_view text) noexcept {
    write_stderr("glove-denial-replay: ", text);
}

void usage(std::string_view text) noexcept {
    write_stderr("usage: glove-denial-replay ", text);
}

// Writes TEXT and a newline to stdout; false on a short write.
auto emit(std::string_view text) -> bool {
    return std::fwrite(text.data(), 1, text.size(), stdout) == text.size() &&
           std::fputc('\n', stdout) != EOF;
}

struct session {
    std::size_t index = 0;
    std::string split;
    bool misbehaving = false;
    std::chrono::milliseconds onset{0};
    container::denial_trace trace;
};

auto read_bounded(const std::filesystem::path& path, std::size_t max_bytes)
    -> std::expected<std::string, std::string> {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > max_bytes) {
        return std::unexpected(path.string() + ": missing or larger than its bound");
    }
    std::ifstream stream{path, std::ios::binary};
    std::string text{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
    if (!stream.good() && !stream.eof()) {
        return std::unexpected(path.string() + ": read failed");
    }
    if (text.size() > max_bytes) {
        return std::unexpected(path.string() + ": larger than its bound");
    }
    return text;
}

auto load_manifest(const std::filesystem::path& path)
    -> std::expected<std::vector<session>, std::string> {
    auto text = read_bounded(path, max_manifest_bytes);
    if (!text) {
        return std::unexpected(text.error());
    }
    const auto base = path.parent_path();
    std::vector<session> out;
    std::string_view rest = *text;
    std::size_t line_number = 0;
    while (!rest.empty()) {
        const auto newline = rest.find('\n');
        const auto line = rest.substr(0, newline);
        rest.remove_prefix(newline == std::string_view::npos ? rest.size() : newline + 1);
        ++line_number;
        if (line.empty()) {
            continue;
        }
        const auto where = path.string() + ":" + std::to_string(line_number) + ": ";
        replay::manifest_line entry;
        if (glz::read<strict_line>(entry, line)) {
            return std::unexpected(where + "not a manifest line");
        }
        const bool misbehaving = entry.label == "misbehaving";
        if ((!misbehaving && entry.label != "benign") || entry.split.empty() ||
            entry.split.size() > 32 || entry.onset_ms < 0 || entry.trace.empty()) {
            return std::unexpected(where + "label, split, onset or trace is invalid");
        }
        if (out.size() == max_manifest_sessions) {
            return std::unexpected(where + "too many sessions");
        }
        std::filesystem::path trace_path{entry.trace};
        if (trace_path.is_relative()) {
            trace_path = base / trace_path;
        }
        auto trace_text = read_bounded(trace_path, container::max_denial_trace_bytes);
        if (!trace_text) {
            return std::unexpected(where + trace_text.error());
        }
        auto trace = container::parse_denial_trace(*trace_text);
        if (!trace) {
            return std::unexpected(where + trace.error());
        }
        out.push_back({
            .index = out.size(),
            .split = std::move(entry.split),
            .misbehaving = misbehaving,
            .onset = std::chrono::milliseconds{entry.onset_ms},
            .trace = std::move(*trace),
        });
    }
    return out;
}

struct decision_point {
    std::chrono::milliseconds at{0};
    container::denial_features features{};
};

// The decision points of one session: after each denial, in order.
auto replay_session(const session& item, double& features_ns, std::uint64_t& feature_calls)
    -> std::vector<decision_point> {
    container::denial_feature_builder builder{item.trace.context};
    std::vector<decision_point> points;
    points.reserve(item.trace.events.size());
    for (const auto& event : item.trace.events) {
        builder.observe(event.denial, event.at);
        const auto started = clock_type::now();
        const auto features = builder.features(event.at);
        features_ns += static_cast<double>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(clock_type::now() - started)
                .count()
        );
        ++feature_calls;
        points.push_back({.at = event.at, .features = features});
    }
    return points;
}

auto percentile(std::vector<std::int64_t> values, double fraction) -> std::int64_t {
    if (values.empty()) {
        return -1;
    }
    std::ranges::sort(values);
    const auto at = static_cast<std::size_t>(fraction * static_cast<double>(values.size() - 1));
    return values.at(at);
}

auto percentile(std::vector<double>& values, double fraction) -> double {
    if (values.empty()) {
        return 0.0;
    }
    std::ranges::sort(values);
    const auto at = static_cast<std::size_t>(fraction * static_cast<double>(values.size() - 1));
    return values.at(at);
}

void finish(replay::confusion& level, std::vector<std::int64_t> latencies) {
    const auto ratio = [](std::uint64_t num, std::uint64_t den) {
        return den == 0 ? 0.0 : static_cast<double>(num) / static_cast<double>(den);
    };
    level.precision = ratio(level.true_positive, level.true_positive + level.false_positive);
    level.recall = ratio(level.true_positive, level.true_positive + level.false_negative);
    level.false_positive_rate =
        ratio(level.false_positive, level.false_positive + level.true_negative);
    level.latency_ms_p50 = percentile(latencies, 0.5);
    level.latency_ms_p90 = percentile(std::move(latencies), 0.9);
}

struct replayed {
    const session* item;
    std::vector<decision_point> points;
};

void score(
    replay::confusion& level,
    std::vector<std::int64_t>& latencies,
    const session& item,
    std::optional<std::chrono::milliseconds> first
) {
    if (!item.misbehaving) {
        ++(first ? level.false_positive : level.true_negative);
        return;
    }
    if (!first) {
        ++level.false_negative;
        return;
    }
    ++level.true_positive;
    if (*first < item.onset) {
        ++level.before_onset;
    } else {
        latencies.push_back((*first - item.onset).count());
    }
}

auto evaluate_arm(const container::denial_decider& arm, const std::vector<replayed>& sessions)
    -> replay::arm_report {
    replay::arm_report report;
    report.arm = std::string{arm.arm()};
    std::vector<std::int64_t> flag_latency;
    std::vector<std::int64_t> terminate_latency;
    std::vector<double> samples;
    double total_ns = 0.0;
    std::uint64_t calls = 0;
    for (const auto& [item, points] : sessions) {
        std::optional<std::chrono::milliseconds> first_flag;
        std::optional<std::chrono::milliseconds> first_terminate;
        for (const auto& point : points) {
            const auto started = clock_type::now();
            const auto decision = arm.decide(point.features);
            const auto spent = static_cast<double>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(clock_type::now() - started)
                    .count()
            );
            total_ns += spent;
            ++calls;
            if (samples.size() < max_timing_samples) {
                samples.push_back(spent);
            }
            if (decision.verdict != container::denial_verdict::proceed && !first_flag) {
                first_flag = point.at;
            }
            if (decision.verdict == container::denial_verdict::terminate && !first_terminate) {
                first_terminate = point.at;
            }
        }
        score(report.flag, flag_latency, *item, first_flag);
        score(report.terminate, terminate_latency, *item, first_terminate);
    }
    finish(report.flag, std::move(flag_latency));
    finish(report.terminate, std::move(terminate_latency));
    report.decide_ns_mean = calls == 0 ? 0.0 : total_ns / static_cast<double>(calls);
    report.decide_ns_p50 = percentile(samples, 0.5);
    report.decide_ns_p99 = percentile(samples, 0.99);
    return report;
}

auto run_rows(std::span<const std::string_view> args) -> int {
    if (args.size() != 1) {
        usage("rows <manifest>");
        return 2;
    }
    auto sessions = load_manifest(std::filesystem::path{args.front()});
    if (!sessions) {
        complain(sessions.error());
        return 1;
    }
    double ignored_ns = 0.0;
    std::uint64_t ignored_calls = 0;
    for (const auto& item : *sessions) {
        for (const auto& point : replay_session(item, ignored_ns, ignored_calls)) {
            const replay::row out{
                .session = item.index,
                .split = item.split,
                .label = item.misbehaving && point.at >= item.onset ? 1 : 0,
                .t_ms = point.at.count(),
                .features = {point.features.begin(), point.features.end()},
            };
            auto line = glz::write_json(out);
            if (!line) {
                complain("encode row failed");
                return 1;
            }
            line->push_back('\n');
            if (std::fwrite(line->data(), 1, line->size(), stdout) != line->size()) {
                return 1;
            }
        }
    }
    return std::fflush(stdout) == 0 ? 0 : 1;
}

struct evaluate_args {
    std::string_view manifest;
    std::optional<std::string_view> model;
    std::vector<std::string> splits;
};

auto parse_evaluate_args(std::span<const std::string_view> args) -> std::optional<evaluate_args> {
    std::optional<std::string_view> manifest;
    evaluate_args out;
    for (std::size_t index = 0; index < args.size(); ++index) {
        const auto arg = args.subspan(index).front();
        if ((arg == "--model" || arg == "--split") && index + 1 < args.size()) {
            const auto value = args.subspan(++index).front();
            if (arg == "--model") {
                out.model = value;
            } else {
                out.splits.emplace_back(value);
            }
        } else if (!arg.starts_with("--") && !manifest) {
            manifest = arg;
        } else {
            return std::nullopt;
        }
    }
    if (!manifest) {
        return std::nullopt;
    }
    out.manifest = *manifest;
    if (out.splits.empty()) {
        out.splits = {"test", "real"};
    }
    return out;
}

// The heuristic arm, then the model arm when a model file was given.
auto load_arms(std::optional<std::string_view> model_path)
    -> std::expected<std::vector<std::unique_ptr<container::denial_decider>>, std::string> {
    std::vector<std::unique_ptr<container::denial_decider>> arms;
    arms.push_back(container::make_heuristic_denial_decider());
    if (model_path) {
        auto text = read_bounded(std::filesystem::path{*model_path}, max_model_bytes);
        if (!text) {
            return std::unexpected(text.error());
        }
        auto model = container::load_denial_model(*text);
        if (!model) {
            return std::unexpected(model.error());
        }
        arms.push_back(std::move(*model));
    }
    return arms;
}

auto run_evaluate(std::span<const std::string_view> args) -> int {
    const auto parsed = parse_evaluate_args(args);
    if (!parsed) {
        usage("evaluate <manifest> [--model <file>] [--split <name>]...");
        return 2;
    }
    const auto& splits = parsed->splits;
    auto arms = load_arms(parsed->model);
    if (!arms) {
        complain(arms.error());
        return 1;
    }
    auto sessions = load_manifest(std::filesystem::path{parsed->manifest});
    if (!sessions) {
        complain(sessions.error());
        return 1;
    }
    replay::evaluation report;
    report.timing_build = std::string{timing_build()};
    report.splits = splits;
    double features_ns = 0.0;
    std::uint64_t feature_calls = 0;
    std::vector<replayed> chosen;
    for (const auto& item : *sessions) {
        if (std::ranges::find(splits, item.split) == splits.end()) {
            continue;
        }
        chosen.push_back(
            {.item = &item, .points = replay_session(item, features_ns, feature_calls)}
        );
        ++report.sessions;
        report.misbehaving += item.misbehaving ? 1 : 0;
        report.decision_points += chosen.back().points.size();
    }
    report.features_ns_mean =
        feature_calls == 0 ? 0.0 : features_ns / static_cast<double>(feature_calls);
    for (const auto& arm : *arms) {
        report.arms.push_back(evaluate_arm(*arm, chosen));
    }
    auto json = glz::write<glz::opts{.prettify = true}>(report);
    if (!json) {
        complain("encode report failed");
        return 1;
    }
    return emit(*json) && std::fflush(stdout) == 0 ? 0 : 1;
}

auto dispatch(std::span<char*> argv) -> int {
    const std::vector<std::string_view> args(argv.begin() + 1, argv.end());
    if (args.empty()) {
        usage("schema|rows|evaluate ...");
        return 2;
    }
    const std::span<const std::string_view> rest{args.begin() + 1, args.end()};
    if (args.front() == "schema" && rest.empty()) {
        std::string out = R"({"feature_schema":)" +
                          std::to_string(container::denial_feature_schema_version) +
                          R"(,"features":[)";
        bool first = true;
        for (const auto name : container::denial_feature_names()) {
            out += (first ? "\"" : ",\"") + std::string{name} + "\"";
            first = false;
        }
        out += "]}";
        return emit(out) && std::fflush(stdout) == 0 ? 0 : 1;
    }
    if (args.front() == "rows") {
        return run_rows(rest);
    }
    if (args.front() == "evaluate") {
        return run_evaluate(rest);
    }
    usage("schema|rows|evaluate ...");
    return 2;
}

} // namespace

auto main(int argc, char** argv) -> int {
    try {
        return dispatch({argv, static_cast<std::size_t>(argc)});
    } catch (const std::exception& error) {
        complain(error.what());
    } catch (...) {
        complain("unexpected failure");
    }
    return 1;
}
