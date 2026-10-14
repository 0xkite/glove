#include "pi_cli.hpp"
#include "pi_launch_fixture.hpp"
#include "pi_machine_authorities.hpp"

#include <cstdio>

namespace {
namespace fs = std::filesystem;
using glove::run::test_support::fixture;
using glove::run::test_support::launch_pi_with_context;
using glove::run::test_support::named;
using glove::run::test_support::read_file;
using glove::run::test_support::temporary_directory;
using glove::run::test_support::write_file;

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

auto same_control_file(const struct stat& before, const struct stat& after) -> bool {
    return before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
           before.st_mode == after.st_mode && before.st_uid == after.st_uid &&
           before.st_gid == after.st_gid && before.st_nlink == after.st_nlink &&
           before.st_size == after.st_size &&
           before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
           before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
           before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
           before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
}

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    fixture consumer{temporary.root() / "consumer"};
    REQUIRE(consumer.prepare() == 0);
    const auto control = consumer.source() / "external-control.key";
    constexpr std::string_view bytes = "fixture-only-external-control-state\n";
    REQUIRE(write_file(control, bytes));
    auto restaged = glove::host::stage_runtime_harness(
        {.runtime_id = "pi",
         .source_executable = consumer.source() / "bin/pi",
         .protected_directory = consumer.runtime_store(),
         .dry_run = false}
    );
    REQUIRE(restaged);
    consumer.saved.runtime = *restaged;
    auto stored =
        glove::run::store_pi_runtime_selection(consumer.record(), consumer.saved, true, true);
    REQUIRE(stored && *stored);
    REQUIRE(glove::host::validate_pi_runtime_harness(consumer.saved.runtime));
    // The same ordinary resource is admissible until trusted policy names it
    // as control authority. No filename-based secret stripping is exercised.
    auto positive = launch_pi_with_context(consumer.request(), consumer.context, {});
    REQUIRE(positive && *positive == 7 && !consumer.observed.inspection_failed);
    REQUIRE(
        consumer.observed.credentials == 1 && consumer.observed.starts == 1 &&
        consumer.observed.executions == 1
    );
    REQUIRE(consumer.audit_has_no_key() == 0);
    const auto record_before = read_file(consumer.record());
    struct stat before{};
    REQUIRE(::lstat(control.c_str(), &before) == 0);
    consumer.observed = {};
    consumer.observed.runs = consumer.context.directories.runtime / "pi/runs";
    const auto ordinary_roots = consumer.context.protected_auth_roots;
    consumer.context.protected_auth_roots.push_back(control);
    auto consumed = launch_pi_with_context(consumer.request(), consumer.context, {});
    const bool consumer_refused =
        !consumed && consumed.error().contains("Pi source closure overlaps operator state");
    const bool before_authority = consumer.observed.credentials == 0 &&
                                  consumer.observed.starts == 0 &&
                                  consumer.observed.executions == 0;
    REQUIRE(read_file(consumer.record()) == record_before);
    REQUIRE(consumer.audit_has_no_key() == 0);

    fixture producer{temporary.root() / "producer"};
    REQUIRE(producer.prepare(false) == 0);
    glove::host::config config{};
    config.runtime_directory = producer.context.directories.runtime;
    config.audit_key = control;
    config.receipt_journal = producer.context.directories.state / "receipts.jsonl";
    auto encoded = glove::host::encode_config(config);
    REQUIRE(encoded);
    const auto config_path = glove::host::default_config_path(producer.context.directories);
    REQUIRE(write_file(config_path, *encoded));
    const auto config_before = read_file(config_path);
    int detections = 0;
    int stages = 0;
    glove::run::detail::pi_setup_context setup{
        .directories = producer.context.directories,
        .detect =
            [&]() {
                ++detections;
                return std::vector<glove::host::detected_runtime_harness>{
                    {.runtime_id = "pi",
                     .executable_name = "pi",
                     .available = true,
                     .resolved_executable = consumer.source() / "bin/pi",
                     .diagnostic = {}}
                };
            },
        .stage =
            [&](const glove::host::runtime_harness_stage_options& options) {
                ++stages;
                return glove::host::stage_runtime_harness(options);
            }
    };
    const glove::run::detail::pi_command_line command{
        .action = glove::run::detail::pi_command_action::setup,
        .request =
            {.selection = {.provider = "openai", .model = "gpt-5", .arguments = {}},
             .workspace = std::nullopt},
        .approved = true
    };
    auto produced = glove::run::detail::configure_pi_runtime(command, setup);
    const bool producer_refused =
        !produced && produced.error().contains("Pi source closure overlaps operator state");
    const bool no_publication = !named(producer.record()) &&
                                !named(producer.runtime_store() / "pi") &&
                                !named(producer.runtime_store() / "snapshots");
    struct stat after{};
    REQUIRE(::lstat(control.c_str(), &after) == 0);
    REQUIRE(same_control_file(before, after) && read_file(control) == bytes);
    REQUIRE(read_file(config_path) == config_before);
    std::fprintf(
        stderr,
        "configured source authority: consumer=%d before-authority=%d producer=%d "
        "unpublished=%d detections=%d stages=%d\n",
        consumer_refused,
        before_authority,
        producer_refused,
        no_publication,
        detections,
        stages
    );
    REQUIRE(consumer_refused && before_authority && producer_refused && no_publication);

    // An external authority alias must reserve its resolved source location.
    const auto alias = temporary.root() / "control-alias";
    fs::create_symlink(control, alias);
    consumer.context.protected_auth_roots = ordinary_roots;
    consumer.context.protected_auth_roots.push_back(alias);
    auto aliased = launch_pi_with_context(consumer.request(), consumer.context, {});
    REQUIRE(!aliased && aliased.error().contains("Pi source closure overlaps operator state"));
    REQUIRE(
        consumer.observed.credentials == 0 && consumer.observed.starts == 0 &&
        consumer.observed.executions == 0
    );
    // Missing control state still reserves its lexical location before copying.
    consumer.context.protected_auth_roots = ordinary_roots;
    consumer.context.protected_auth_roots.push_back(consumer.source() / "future-control.key");
    auto missing = launch_pi_with_context(consumer.request(), consumer.context, {});
    REQUIRE(!missing && missing.error().contains("Pi source closure overlaps operator state"));
    REQUIRE(
        consumer.observed.credentials == 0 && consumer.observed.starts == 0 &&
        consumer.observed.executions == 0
    );
    REQUIRE(read_file(consumer.record()) == record_before);

    using glove::run::detail::pi_source_authorities;
    const std::vector<fs::path> too_many(65U, temporary.root() / "disjoint");
    REQUIRE(!pi_source_authorities(consumer.context.directories, too_many));
    for (const auto& invalid :
         {fs::path{"relative"},
          fs::path{"/"},
          temporary.root() / "../not-normalized",
          fs::path{std::string{"/nul\0path", 9U}},
          fs::path{"/" + std::string(4096U, 'x')}}) {
        const std::array roots{invalid};
        REQUIRE(!pi_source_authorities(consumer.context.directories, roots));
    }
    const std::vector<fs::path> repeated(64U, temporary.root() / "disjoint");
    auto bounded = pi_source_authorities(consumer.context.directories, repeated);
    REQUIRE(bounded && bounded->size() == 6U);

    // Optional control config is absent only for genuine ENOENT. Unsafe/malformed
    // existing bytes must fail before even synthetic discovery/staging callbacks.
    REQUIRE(write_file(config_path, "{malformed"));
    auto malformed = glove::run::detail::configure_pi_runtime(command, setup);
    REQUIRE(!malformed && malformed.error().contains("unsafe host control configuration"));
    REQUIRE(detections == 1 && stages == 1);
    REQUIRE(write_file(config_path, config_before));
    REQUIRE(::chmod(config_path.c_str(), 0644) == 0);
    auto unsafe = glove::run::detail::configure_pi_runtime(command, setup);
    REQUIRE(!unsafe && unsafe.error().contains("unsafe host control configuration"));
    REQUIRE(detections == 1 && stages == 1);
    REQUIRE(::chmod(config_path.c_str(), 0600) == 0);
    REQUIRE(read_file(config_path) == config_before);
    REQUIRE(::lstat(control.c_str(), &after) == 0 && same_control_file(before, after));
    REQUIRE(read_file(control) == bytes);
    return 0;
}
} // namespace

auto main() -> int {
    return run();
}
