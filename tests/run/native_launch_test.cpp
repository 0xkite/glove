#include "adapters/pi/native_harness.hpp"
#include "native_launch.hpp"
#include "native_library_environment.hpp"
#include "pi_launch_fixture.hpp"
#include "pi_launch_internal.hpp"
#include "pi_native_policy.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

namespace {
#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

namespace fs = std::filesystem;
using namespace glove::run::detail;
using glove::run::test_support::fixture;
using glove::run::test_support::named;
using glove::run::test_support::read_file;
using glove::run::test_support::temporary_directory;

// Fault projections only: no second production harness and no parallel mock
// launch lifecycle. Every refusal enters the same core as production Pi.
class fault_projection final : public native_harness_adapter {
public:
    explicit fault_projection(unsigned mutation, bool after_binding = false)
        : mutation_{mutation}, after_binding_{after_binding} {}

    mutable unsigned calls = 0;

    auto encode_startup(const native_startup_input& input) const
        -> std::expected<native_startup_recipe, std::string> override {
        ++calls;
        auto recipe = delegate_.encode_startup(input);
        if (!recipe || (after_binding_ && calls == 1)) {
            return recipe;
        }
        switch (mutation_) {
        case 0:
            recipe->argv.pop_back();
            break;
        case 1:
            recipe->environment.push_back(
                {.name = "NODE_PATH",
                 .location = native_private_location::agent,
                 .source = native_environment_source::private_location,
                 .literal = {}}
            );
            break;
        case 2:
            recipe->environment.clear();
            break;
        case 3:
            recipe->environment.front().location = native_private_location::config;
            break;
        case 4:
            recipe->configuration.erase(recipe->configuration.begin());
            break;
        case 5:
            recipe->configuration.front().name = "../auth.json";
            break;
        case 6:
            recipe->argv.insert(recipe->argv.begin() + 1, "--require=/host");
            break;
        case 7:
            recipe->reserved_entries.clear();
            break;
        case 8:
            recipe->configuration.front().bytes.assign(32769, 'x');
            break;
        case 9:
            recipe->argv.resize(129, "x");
            break;
        case 10:
            recipe->base_url = "http://127.0.0.1:2/openai/v1";
            break;
        case 11:
            recipe->configuration.back().name = "AUTH.JSON";
            break;
        default:
            return std::unexpected("invalid synthetic mutation");
        }
        return recipe;
    }

private:
    unsigned mutation_;
    bool after_binding_;
    glove::run::adapters::pi_harness_adapter delegate_;
};

auto malformed_projection_cases(const fs::path& root) -> int {
    for (unsigned mutation = 0; mutation < 12; ++mutation) {
        fixture f{root / ("projection-" + std::to_string(mutation))};
        REQUIRE(f.prepare() == 0);
        const auto record = read_file(f.record());
        const fault_projection adapter{mutation};
        const auto refused = launch_pi_with_adapter(f.request(), f.context, adapter);
        REQUIRE(!refused && adapter.calls == 1);
        REQUIRE(
            f.observed.credentials == 0 && f.observed.starts == 0 && f.observed.executions == 0
        );
        REQUIRE(!named(f.observed.runs));
        REQUIRE(read_file(f.record()) == record);
        REQUIRE(f.audit_has_no_key() == 0);
    }
    return 0;
}

auto post_binding_projection_cases(const fs::path& root) -> int {
    for (unsigned mutation : {0U, 1U, 4U, 7U, 8U, 10U}) {
        fixture f{root / ("bound-projection-" + std::to_string(mutation))};
        REQUIRE(f.prepare() == 0);
        const auto record = read_file(f.record());
        const fault_projection adapter{mutation, true};
        const auto refused = launch_pi_with_adapter(f.request(), f.context, adapter);
        REQUIRE(!refused && adapter.calls == 2);
        REQUIRE(
            f.observed.credentials == 1 && f.observed.starts == 1 && f.observed.executions == 0
        );
        REQUIRE(f.observed.revoked && f.observed.joined);
        // The fixture returns -1 for absent/unreadable runs; the independent
        // named-directory check below establishes absence, not process death.
        REQUIRE(f.observed.roots_at_reset == -1);
        REQUIRE(!named(f.observed.runs));
        REQUIRE(read_file(f.record()) == record);
        REQUIRE(f.audit_has_no_key() == 0);
    }
    return 0;
}

auto unsupported_authority_cases(const fs::path& root) -> int {
    for (const bool unsupported_backend : {false, true}) {
        fixture f{root / (unsupported_backend ? "backend" : "provider")};
        REQUIRE(f.prepare() == 0);
        unsigned admissions = 0;
        unsigned assets = 0;
        unsigned rechecks = 0;
        native_launch_context context{
            .directories = f.context.directories,
            .protected_auth_roots = f.context.protected_auth_roots,
            .workspace = f.workspace(),
            .runs = f.context.directories.runtime / "pi/runs",
            .policy = pi_native_startup_policy(),
            .display_name = "Pi",
            .backend = unsupported_backend ? native_launch_backend::unsupported
                                           : native_launch_backend::macos,
            .admit_runtime = [&]() -> std::expected<native_launch_binding, std::string> {
                ++admissions;
                return native_launch_binding{
                    .runtime = f.saved.runtime,
                    .provider = static_cast<glove::net::endpoint_provider>(99),
                    .model = f.saved.model.model,
                    .arguments = {}
                };
            },
            .admit_assets = [&](const native_launch_binding&)
                -> std::expected<native_launch_assets, std::string> {
                ++assets;
                return std::unexpected("unexpected synthetic asset admission");
            },
            .revalidate = [&]() -> std::expected<native_launch_authority, std::string> {
                ++rechecks;
                return std::unexpected("unexpected synthetic revalidation");
            },
            .credential =
                [&](glove::net::endpoint_provider) -> std::expected<std::string, std::string> {
                ++f.observed.credentials;
                return std::unexpected("unexpected synthetic credential mediation");
            },
            .start_endpoint = f.context.start_endpoint,
            .execute_owned = f.context.execute_owned,
            .audit = f.context.audit,
            .conversation_id = {},
            .resume = false,
            .materialize = {},
            .on_launching = {},
            .finalize = {}
        };
        const fault_projection adapter{0};
        const auto refused = launch_native_with_context(context, adapter);
        REQUIRE(!refused);
        REQUIRE(admissions == (unsupported_backend ? 0U : 1U));
        REQUIRE(assets == 0 && rechecks == 0 && adapter.calls == 0);
        REQUIRE(
            f.observed.credentials == 0 && f.observed.starts == 0 && f.observed.executions == 0
        );
        REQUIRE(!named(f.observed.runs));
        REQUIRE(f.audit_has_no_key() == 0);
    }
    return 0;
}

auto library_layout_compatibility(const fs::path& root) -> int {
    // Isolated metadata/projection unit fixtures, not proof of host snapshot
    // digest admission or installed Pi layout compatibility.
    for (bool alias : {false, true}) {
        const auto payload = root / (alias ? "library-alias" : "library-file");
        const auto copied = payload / "root-0";
        fs::create_directories(copied);
        if (alias) {
            fs::create_directory(copied / "lib-real");
            REQUIRE(
                glove::run::test_support::write_file(copied / "lib-real/resource", "resource", 0400)
            );
            REQUIRE(::chmod((copied / "lib-real").c_str(), 0500) == 0);
            fs::create_symlink("lib-real", copied / "lib");
        } else {
            REQUIRE(glove::run::test_support::write_file(copied / "lib", "not a directory", 0400));
        }
        REQUIRE(::chmod(copied.c_str(), 0500) == 0);
        REQUIRE(::chmod(payload.c_str(), 0500) == 0);
        glove::host::staged_runtime_harness runtime{};
        runtime.read_only_paths = {payload};
        runtime.source_read_only_paths = {root / "unread-source-placeholder"};
        const std::vector<std::string> environment =
            alias ? std::vector<std::string>{"DYLD_LIBRARY_PATH=" + (copied / "lib").string()}
                  : std::vector<std::string>{};
        REQUIRE(validate_native_library_environment(runtime, environment));
    }
    return 0;
}

auto nested_library_alias(const fs::path& root) -> int {
    const auto payload = root / "nested-library-alias";
    const auto copied = payload / "root-0";
    fs::create_directories(copied / "sub/deep");
    fs::create_directory(copied / "sub/b");
    REQUIRE(glove::run::test_support::write_file(copied / "b", "not a directory", 0400));
    fs::create_symlink("sub/deep", copied / "a");
    fs::create_symlink("a/../b", copied / "lib");
    for (const auto& path :
         {copied / "sub/deep", copied / "sub/b", copied / "sub", copied, payload}) {
        REQUIRE(::chmod(path.c_str(), 0500) == 0);
    }
    REQUIRE(fs::is_directory(copied / "lib"));
    glove::host::staged_runtime_harness runtime{};
    runtime.read_only_paths = {payload};
    runtime.source_read_only_paths = {root / "unread-source-placeholder"};
    const std::vector<std::string> environment{"DYLD_LIBRARY_PATH=" + (copied / "lib").string()};
    REQUIRE(validate_native_library_environment(runtime, environment));
    return 0;
}

auto missing_library_alias_component(const fs::path& root) -> int {
    const auto payload = root / "missing-alias-component";
    const auto copied = payload / "root-0";
    fs::create_directories(copied / "b");
    fs::create_symlink("missing/../b", copied / "lib");
    for (const auto& path : {copied / "b", copied, payload}) {
        REQUIRE(::chmod(path.c_str(), 0500) == 0);
    }
    std::error_code error;
    REQUIRE(!fs::is_directory(copied / "lib", error));
    glove::host::staged_runtime_harness runtime{};
    runtime.read_only_paths = {payload};
    runtime.source_read_only_paths = {root / "unread-source-placeholder"};
    REQUIRE(validate_native_library_environment(runtime, {}));
    return 0;
}

auto library_alias_refusals(const fs::path& root) -> int {
    for (unsigned variant = 0; variant < 4; ++variant) {
        const auto payload = root / ("alias-refusal-" + std::to_string(variant));
        const auto copied = payload / "root-0";
        fs::create_directories(copied);
        if (variant == 3) {
            fs::create_symlink(".", copied / "a");
        }
        const fs::path target = variant == 0   ? fs::path{"../../outside"}
                                : variant == 1 ? root / "outside"
                                : variant == 2 ? fs::path{"lib"}
                                               : fs::path{"a/../../outside"};
        fs::create_symlink(target, copied / "lib");
        REQUIRE(::chmod(copied.c_str(), 0500) == 0);
        REQUIRE(::chmod(payload.c_str(), 0500) == 0);
        glove::host::staged_runtime_harness runtime{};
        runtime.read_only_paths = {payload};
        runtime.source_read_only_paths = {root / "unread-source-placeholder"};
        const std::vector<std::string> environment{
            "DYLD_LIBRARY_PATH=" + (copied / "lib").string()
        };
        REQUIRE(!validate_native_library_environment(runtime, environment));
    }
    return 0;
}

auto revalidated_library_refusal(const fs::path& root) -> int {
    fixture f{root / "revalidated-library"};
    REQUIRE(f.prepare() == 0);
    auto libraries = glove::run::pi_runtime_library_environment(f.saved);
    REQUIRE(libraries);
    const auto binding = [&] {
        return native_launch_binding{
            .runtime = f.saved.runtime,
            .provider = glove::net::endpoint_provider::openai,
            .model = f.saved.model.model,
            .arguments = f.request().selection.arguments
        };
    };
    native_launch_context context{
        .directories = f.context.directories,
        .protected_auth_roots = f.context.protected_auth_roots,
        .workspace = f.workspace(),
        .runs = f.context.directories.runtime / "pi/runs",
        .policy = pi_native_startup_policy(),
        .display_name = "Pi",
        .backend = native_launch_backend::macos,
        .admit_runtime = [&]() -> std::expected<native_launch_binding, std::string> {
            return binding();
        },
        .admit_assets =
            [&](const native_launch_binding&) -> std::expected<native_launch_assets, std::string> {
            return native_launch_assets{
                .catalog_json = std::string{glove::run::test_support::openai_catalog},
                .library_environment = *libraries
            };
        },
        .revalidate = [&]() -> std::expected<native_launch_authority, std::string> {
            return native_launch_authority{
                .binding = binding(),
                .assets = {
                    .catalog_json = std::string{glove::run::test_support::openai_catalog},
                    .library_environment = {"NODE_PATH=/synthetic"}
                }
            };
        },
        .credential =
            [&](glove::net::endpoint_provider) -> std::expected<std::string, std::string> {
            return f.context.credential(glove::run::pi_provider::openai);
        },
        .start_endpoint = f.context.start_endpoint,
        .execute_owned = f.context.execute_owned,
        .audit = f.context.audit,
        .conversation_id = {},
        .resume = false,
        .materialize = {},
        .on_launching = {},
        .finalize = {}
    };
    const glove::run::adapters::pi_harness_adapter adapter;
    const auto refused = launch_native_with_context(context, adapter);
    REQUIRE(!refused && refused.error() == "invalid native library projection");
    REQUIRE(f.observed.credentials == 1 && f.observed.starts == 1 && f.observed.executions == 0);
    REQUIRE(f.observed.revoked && f.observed.joined && f.observed.roots_at_reset == 1);
    REQUIRE(glove::run::test_support::named_run_count(f.observed.runs) == 0);
    REQUIRE(f.audit_has_no_key() == 0);
    return 0;
}

auto library_authority_refusal(const fs::path& root) -> int {
    fixture f{root / "library-authority"};
    REQUIRE(f.prepare() == 0);
    const auto mapped = (f.saved.runtime.read_only_paths.front() / "root-0/lib").string();
    const std::string prefix = "DYLD_LIBRARY_PATH=";
    std::string too_many = prefix;
    for (unsigned index = 0; index < 65; ++index) {
        if (index != 0) {
            too_many += ':';
        }
        too_many += "/synthetic/lib-" + std::to_string(index);
    }
    const std::vector<std::vector<std::string>> invalid{
        {"OPENAI_API_KEY=synthetic-sentinel"},
        {"NODE_PATH=/synthetic"},
        {"LD_LIBRARY_PATH=" + mapped},
        {prefix},
        {prefix + "/usr/lib"},
        {prefix + mapped, prefix + mapped},
        {prefix + std::string(32769, 'x')},
        {prefix + mapped + ':'},
        {prefix + ':' + mapped},
        {prefix + mapped + ':' + mapped},
        {prefix + mapped + "/../lib"},
        {prefix + mapped + '/'},
        {prefix + mapped + "//child"},
        {prefix + std::string{"/tmp\0ignored", 12}},
        {too_many}
    };
    std::vector<std::string> projection;
    native_launch_context context{
        .directories = f.context.directories,
        .protected_auth_roots = f.context.protected_auth_roots,
        .workspace = f.workspace(),
        .runs = f.context.directories.runtime / "pi/runs",
        .policy = pi_native_startup_policy(),
        .display_name = "Pi",
        .backend = native_launch_backend::macos,
        .admit_runtime = [&]() -> std::expected<native_launch_binding, std::string> {
            return native_launch_binding{
                .runtime = f.saved.runtime,
                .provider = glove::net::endpoint_provider::openai,
                .model = f.saved.model.model,
                .arguments = {}
            };
        },
        .admit_assets =
            [&](const native_launch_binding&) -> std::expected<native_launch_assets, std::string> {
            return native_launch_assets{
                .catalog_json = std::string{glove::run::test_support::openai_catalog},
                .library_environment = projection
            };
        },
        .revalidate = []() -> std::expected<native_launch_authority, std::string> {
            return std::unexpected("unexpected revalidation");
        },
        .credential =
            [&](glove::net::endpoint_provider) -> std::expected<std::string, std::string> {
            ++f.observed.credentials;
            return std::unexpected("synthetic credential boundary reached");
        },
        .start_endpoint = f.context.start_endpoint,
        .execute_owned = f.context.execute_owned,
        .audit = f.context.audit,
        .conversation_id = {},
        .resume = false,
        .materialize = {},
        .on_launching = {},
        .finalize = {}
    };
    const glove::run::adapters::pi_harness_adapter adapter;
    for (const auto& entry : invalid) {
        projection = entry;
        const auto refused = launch_native_with_context(context, adapter);
        REQUIRE(!refused);
        REQUIRE(
            f.observed.credentials == 0 && f.observed.starts == 0 && f.observed.executions == 0
        );
        REQUIRE(!named(f.observed.runs));
    }
    return 0;
}
} // namespace

auto main() -> int {
    temporary_directory root;
    REQUIRE(!root.root().empty());
    REQUIRE(malformed_projection_cases(root.root()) == 0);
    REQUIRE(unsupported_authority_cases(root.root()) == 0);
    REQUIRE(post_binding_projection_cases(root.root()) == 0);
    REQUIRE(library_authority_refusal(root.root()) == 0);
    REQUIRE(library_layout_compatibility(root.root()) == 0);
    REQUIRE(revalidated_library_refusal(root.root()) == 0);
    REQUIRE(library_alias_refusals(root.root()) == 0);
    REQUIRE(nested_library_alias(root.root()) == 0);
    REQUIRE(missing_library_alias_component(root.root()) == 0);
    return 0;
}
