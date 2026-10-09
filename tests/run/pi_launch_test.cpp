#include "glove/audit/sink.hpp"
#include "glove/host/runtime_policy.hpp"
#include "glove/run/pi_runtime.hpp"

#include "launch_command.hpp"
#include "pi_launch_fixture.hpp"
#include "pi_launch_internal.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using glove::net::credentialed_endpoint;
using glove::net::credentialed_endpoint_options;
using glove::net::endpoint_provider;
using glove::run::pi_provider;
using glove::run::detail::launch_pi_with_context;
using glove::run::test_support::anthropic_catalog;
using glove::run::test_support::catalog_suffix;
using glove::run::test_support::fixture;
using glove::run::test_support::host_key;
using glove::run::test_support::marker_name;
using glove::run::test_support::named;
using glove::run::test_support::named_run_count;
using glove::run::test_support::openai_catalog;
using glove::run::test_support::read_file;
using glove::run::test_support::temporary_directory;
using glove::run::test_support::write_file;

auto positive_cases(const fs::path& root) -> int {
    for (const auto provider : {pi_provider::openai, pi_provider::anthropic}) {
        fixture f{root / std::string{glove::run::pi_provider_name(provider)}, provider};
        REQUIRE(f.prepare() == 0);
        const auto before_record = read_file(f.record());
        const auto result = launch_pi_with_context(f.request(), f.context);
        if (!result) {
            const bool sensitive = result.error().find(host_key) != std::string::npos ||
                                   (!f.observed.nonce.empty() &&
                                    result.error().find(f.observed.nonce) != std::string::npos);
            std::fprintf(
                stderr,
                "typed launch refusal: %.1024s\n",
                sensitive ? "<redacted>" : result.error().c_str()
            );
        }
        REQUIRE(result && *result == 7);
        REQUIRE(!f.observed.inspection_failed);
        REQUIRE(
            f.observed.credentials == 1 && f.observed.starts == 1 && f.observed.executions == 1
        );
        REQUIRE(f.observed.revoked && f.observed.joined && f.observed.roots_at_reset == 1);
        REQUIRE(!named(f.observed.root));
        REQUIRE(named_run_count(f.observed.runs) == 0);
        REQUIRE(read_file(f.record()) == before_record);
        REQUIRE(read_file(f.package() / catalog_suffix / "openai.json") == openai_catalog);
        REQUIRE(read_file(f.package() / catalog_suffix / "anthropic.json") == anthropic_catalog);
        REQUIRE(f.audit_has_no_key() == 0);
    }
    return 0;
}

auto execution_error_retains_launching(const fs::path& root) -> int {
    fixture f{root / "execution-error"};
    REQUIRE(f.prepare() == 0);
    // Even a diagnostic that sounds terminal is not owned-quiescence evidence.
    const std::string original = "synthetic executor error: child exited, outcome unknown";
    f.context.execute_owned = [&](const glove::container::profile& profile,
                                  const std::vector<std::string>& argv,
                                  std::stop_token) -> std::expected<int, std::string> {
        ++f.observed.executions;
        if (f.inspect_launch(profile, argv) != 0) {
            f.observed.inspection_failed = true;
        }
        return std::unexpected(original);
    };
    const auto result = launch_pi_with_context(f.request(), f.context);
    REQUIRE(!result && result.error().find(original) != std::string::npos);
    REQUIRE(!f.observed.inspection_failed && f.observed.executions == 1);
    REQUIRE(f.observed.revoked && f.observed.joined && f.observed.roots_at_reset == 1);
    REQUIRE(named(f.observed.root));
    REQUIRE(read_file(f.observed.root / marker_name).ends_with("\nlaunching\n"));
    REQUIRE(result.error().find(host_key) == std::string::npos);
    REQUIRE(f.audit_has_no_key() == 0);
    return 0;
}

auto early_refusals(const fs::path& root) -> int {
    const std::vector<std::vector<std::string>> authority_arguments{
        {"--provider", "anthropic"},
        {"--api-key=credential"},
        {"--session-dir", "/host"},
        {"--extension", "/host"},
        {"--no-tools"},
        {"--", "@/host/auth.json"}
    };
    for (std::size_t index = 0; index < authority_arguments.size() + 5; ++index) {
        fixture f{root / ("early-" + std::to_string(index))};
        const bool missing = index == authority_arguments.size();
        REQUIRE(f.prepare(!missing) == 0);
        auto request = f.request();
        std::stop_source stop;
        if (index < authority_arguments.size()) {
            request.selection.arguments = authority_arguments[index];
        } else if (index == authority_arguments.size() + 1) {
            f.context.credential = [&](pi_provider) -> std::expected<std::string, std::string> {
                ++f.observed.credentials;
                return std::unexpected(std::string{"set OPENAI_API_KEY in the host environment"});
            };
        } else if (index == authority_arguments.size() + 2) {
            request.selection.provider = "custom";
        } else if (index == authority_arguments.size() + 3) {
            REQUIRE(write_file(f.workspace() / ".PI", "untrusted project config"));
        } else if (index == authority_arguments.size() + 4) {
            REQUIRE(stop.request_stop());
        }
        const auto result = launch_pi_with_context(request, f.context, stop.get_token());
        REQUIRE(!result && !result.error().empty());
        REQUIRE(result.error().find(host_key) == std::string::npos);
        REQUIRE(f.observed.starts == 0 && f.observed.executions == 0);
        REQUIRE(!named(f.observed.runs));
        if (missing) {
            REQUIRE(!named(f.record()) && !named(f.runtime_store()));
            REQUIRE(f.observed.credentials == 0);
            REQUIRE(result.error().find("setup") != std::string::npos);
        }
        if (index < authority_arguments.size() || index == authority_arguments.size() + 2 ||
            index == authority_arguments.size() + 4) {
            REQUIRE(f.observed.credentials == 0);
        }
        if (index == authority_arguments.size() + 1) {
            REQUIRE(result.error().find("OPENAI_API_KEY") != std::string::npos);
        }
        if (index == authority_arguments.size() + 3) {
            REQUIRE(read_file(f.workspace() / ".PI") == "untrusted project config");
        }
        REQUIRE(f.audit_has_no_key() == 0);
    }
    return 0;
}

auto workspace_overlap_refusals(const fs::path& root) -> int {
    fixture f{root / "overlap"};
    REQUIRE(f.prepare() == 0);
    const auto& directories = f.context.directories;
    for (const auto& protected_path :
         {directories.config,
          directories.state,
          directories.data,
          directories.cache,
          directories.runtime,
          f.context.protected_auth_roots.front(),
          f.source(),
          f.package(),
          f.saved.runtime.read_only_paths.front()}) {
        auto request = f.request();
        request.workspace = protected_path;
        const auto result = launch_pi_with_context(request, f.context);
        REQUIRE(!result && !result.error().empty());
        REQUIRE(result.error().find(host_key) == std::string::npos);
        REQUIRE(f.observed.starts == 0 && f.observed.executions == 0);
        REQUIRE(!named(f.observed.runs));
    }
    const auto control_file = f.workspace() / "host-control";
    REQUIRE(write_file(control_file, "host control sentinel"));
    f.context.protected_auth_roots.push_back(control_file);
    const auto contains_control = launch_pi_with_context(f.request(), f.context);
    REQUIRE(!contains_control && f.observed.starts == 0 && f.observed.executions == 0);
    REQUIRE(read_file(control_file) == "host control sentinel");
    REQUIRE(!named(f.observed.runs));
    REQUIRE(f.audit_has_no_key() == 0);
    return 0;
}

auto endpoint_failure_precedes_private_writes(const fs::path& root) -> int {
    fixture f{root / "endpoint-error"};
    REQUIRE(f.prepare() == 0);
    const std::string original = "synthetic endpoint unavailable";
    f.context.start_endpoint = [&](credentialed_endpoint_options)
        -> std::expected<std::unique_ptr<credentialed_endpoint>, std::string> {
        ++f.observed.starts;
        return std::unexpected(original);
    };
    const auto result = launch_pi_with_context(f.request(), f.context);
    REQUIRE(!result && result.error().find(original) != std::string::npos);
    REQUIRE(f.observed.starts == 1 && f.observed.executions == 0);
    REQUIRE(!named(f.observed.runs));
    REQUIRE(!f.observed.revoked && !f.observed.joined);
    REQUIRE(f.audit_has_no_key() == 0);
    return 0;
}

auto preexecution_drift_refusals(const fs::path& root) -> int {
    for (const bool catalog_drift : {false, true}) {
        fixture f{root / (catalog_drift ? "catalog-drift" : "record-drift")};
        REQUIRE(f.prepare() == 0);
        f.context.start_endpoint = [&](credentialed_endpoint_options options)
            -> std::expected<std::unique_ptr<credentialed_endpoint>, std::string> {
            ++f.observed.starts;
            bool changed = f.check_options(options) == 0;
            if (catalog_drift) {
                const auto copied_package =
                    fs::path{f.saved.runtime.launch_arguments.front()}.parent_path().parent_path();
                const auto catalog = copied_package / catalog_suffix / "openai.json";
                changed = (::chmod(catalog.c_str(), 0600) == 0) && changed;
                changed = write_file(catalog, "{}", 0400) && changed;
            } else {
                auto replacement = f.saved;
                replacement.model.model = "approved-refresh-fixture";
                auto stored =
                    glove::run::store_pi_runtime_selection(f.record(), replacement, true, true);
                changed = (stored && *stored) && changed;
            }
            if (!changed) {
                f.observed.inspection_failed = true;
                return std::unexpected(std::string{"synthetic drift fixture failed"});
            }
            return f.endpoint();
        };
        const auto result = launch_pi_with_context(f.request(), f.context);
        REQUIRE(!result && !result.error().empty());
        REQUIRE(!f.observed.inspection_failed);
        REQUIRE(f.observed.options_checked && f.observed.starts == 1 && f.observed.executions == 0);
        REQUIRE(f.observed.revoked && f.observed.joined && f.observed.roots_at_reset == 1);
        REQUIRE(named_run_count(f.observed.runs) == 0);
        REQUIRE(result.error().find(host_key) == std::string::npos);
        // Failed revalidation must not refresh/repair the authority it refused.
        if (!catalog_drift) {
            auto loaded = glove::run::load_pi_runtime_selection(f.record());
            REQUIRE(loaded && *loaded && (*loaded)->model.model == "approved-refresh-fixture");
        } else {
            const auto copied_package =
                fs::path{f.saved.runtime.launch_arguments.front()}.parent_path().parent_path();
            REQUIRE(read_file(copied_package / catalog_suffix / "openai.json") == "{}");
        }
        REQUIRE(f.audit_has_no_key() == 0);
    }
    return 0;
}

auto cleanup_failure_is_reported(const fs::path& root) -> int {
    fixture f{root / "cleanup-error"};
    REQUIRE(f.prepare() == 0);
    f.context.execute_owned = [&](const glove::container::profile& profile,
                                  const std::vector<std::string>& argv,
                                  std::stop_token) -> std::expected<int, std::string> {
        ++f.observed.executions;
        if (f.inspect_launch(profile, argv) != 0 ||
            ::mkfifo((fs::path{*profile.home_dir} / "unsafe-artifact").c_str(), 0600) != 0) {
            f.observed.inspection_failed = true;
            return std::unexpected(std::string{"synthetic artifact fixture failed"});
        }
        return 0;
    };
    const auto result = launch_pi_with_context(f.request(), f.context);
    REQUIRE(!result && !result.error().empty());
    REQUIRE(!f.observed.inspection_failed && f.observed.executions == 1);
    REQUIRE(f.observed.revoked && f.observed.joined && f.observed.roots_at_reset == 1);
    REQUIRE(named(f.observed.root));
    REQUIRE(read_file(f.observed.root / marker_name).ends_with("\nquiescent\n"));
    struct stat info{};
    REQUIRE(
        ::lstat((f.observed.root / "home/unsafe-artifact").c_str(), &info) == 0 &&
        S_ISFIFO(info.st_mode)
    );
    REQUIRE(result.error().find(host_key) == std::string::npos);
    REQUIRE(f.audit_has_no_key() == 0);
    return 0;
}

} // namespace

auto main() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    REQUIRE(positive_cases(temporary.root()) == 0);
    REQUIRE(execution_error_retains_launching(temporary.root()) == 0);
    REQUIRE(early_refusals(temporary.root()) == 0);
    REQUIRE(workspace_overlap_refusals(temporary.root()) == 0);
    REQUIRE(endpoint_failure_precedes_private_writes(temporary.root()) == 0);
    REQUIRE(preexecution_drift_refusals(temporary.root()) == 0);
    REQUIRE(cleanup_failure_is_reported(temporary.root()) == 0);
    return 0;
}
