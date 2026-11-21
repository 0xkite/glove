// Profile validation: round-trip a valid profile, reject the obvious mistakes.

#include "glove/container/profile.hpp"

#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

auto run() -> int {
    {
        constexpr std::string_view tag = "00112233445566778899aabbccddeeff";
        glove::container::profile p;
        p.denial_tag = std::string{tag};
        auto out = glove::container::validate(p);
        REQUIRE(out.has_value());
        REQUIRE(out->denial_tag == std::string{tag});
        for (const std::string& bad :
             {std::string{},
              std::string{tag.substr(0, 31)},
              std::string{"00112233445566778899AABBCCDDEEFF"}}) {
            p.denial_tag = bad;
            auto rejected = glove::container::validate(p);
            REQUIRE(!rejected.has_value());
            REQUIRE(rejected.error() == "denial tag must be 32 lowercase hex characters");
        }
    }

    {
        glove::container::profile p;
        p.filesystem.push_back({.path = "/agent/workspace", .writable = true});
        p.filesystem.push_back({.path = "/usr/lib", .writable = false});
        p.home_dir = "/agent/workspace";
        p.temp_dir = "/agent/workspace/tmp";
        p.environment = {"PATH=/usr/bin:/bin", "XAI_API_KEY=test"};
        auto out = glove::container::validate(p);
        REQUIRE(out.has_value());
        REQUIRE(out->filesystem.size() == 2);
        REQUIRE(out->environment.size() == 2);
    }

    {
        glove::container::profile p;
        p.required_limits = glove::container::resource_limits{
            .cpu_time_ms = 60'000,
            .memory_bytes = 512 * 1024 * 1024,
            .pids = 128,
            .wall_time_ms = 120'000,
            .disk_bytes = 1024 * 1024 * 1024,
            .terminal_output_bytes = 16 * 1024 * 1024,
        };
        auto out = glove::container::validate(p);
        REQUIRE(out.has_value());
        auto unsupported = glove::container::require_resource_enforcement(*out, {});
        REQUIRE(!unsupported.has_value());
        REQUIRE(unsupported.error().find("cpu_time") != std::string::npos);
        REQUIRE(unsupported.error().find("observable_receipts") != std::string::npos);

        glove::container::resource_enforcement_capabilities complete{
            .cpu_time = glove::container::enforcement_mechanism::cgroup_v2,
            .memory = glove::container::enforcement_mechanism::cgroup_v2,
            .pids = glove::container::enforcement_mechanism::cgroup_v2,
            .wall_time = glove::container::enforcement_mechanism::watchdog,
            .disk = glove::container::enforcement_mechanism::filesystem_quota,
            .terminal_output = glove::container::enforcement_mechanism::byte_counter,
            .receipt_schema_version = 1,
        };
        REQUIRE(complete.complete());
        REQUIRE(glove::container::require_resource_enforcement(*out, complete).has_value());

        const std::string profile_digest(64, 'a');
        glove::container::resource_enforcement_receipt receipt{
            .schema_version = 1,
            .profile_digest = profile_digest,
            .backend = glove::container::sandbox_backend::linux_production,
            .backend_id = "linux-production:cgroup-v2",
            .configured_limits = *out->required_limits,
            .mechanisms = complete,
            .observed =
                {
                    .cpu_time_ms = 500,
                    .peak_memory_bytes = 16 * 1024 * 1024,
                    .peak_pids = 2,
                    .wall_time_ms = 750,
                    .disk_bytes = 4096,
                    .terminal_output_bytes = 1024,
                },
            .termination_cause = glove::container::resource_termination_cause::exited,
            .exit_code = 0,
            .started_at_ms = 1'000,
            .finished_at_ms = 1'750,
            .library_projections = {},
            .retained_changes = {},
        };
        REQUIRE(
            glove::container::validate_resource_enforcement_receipt(
                receipt,
                *out->required_limits,
                complete,
                glove::container::sandbox_backend::linux_production,
                profile_digest
            )
                .has_value()
        );

        auto projected = receipt;
        projected.library_projections.push_back({
            .projection_id = "sage-core",
            .destination_alias = "libraries",
            .target_path = "/opt/sage/library-bundles/" + std::string(64U, 'd') + ".json",
            .content_digest = std::string(64U, 'd'),
        });
        REQUIRE(
            glove::container::validate_resource_enforcement_receipt(
                projected,
                *out->required_limits,
                complete,
                glove::container::sandbox_backend::linux_production,
                profile_digest
            )
                .has_value()
        );
        projected.library_projections.front().target_path = "/tmp/library.json";
        REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                     projected,
                     *out->required_limits,
                     complete,
                     glove::container::sandbox_backend::linux_production,
                     profile_digest
        )
                     .has_value());

        auto mismatched_digest = receipt;
        mismatched_digest.profile_digest[0] = 'b';
        REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                     mismatched_digest,
                     *out->required_limits,
                     complete,
                     glove::container::sandbox_backend::linux_production,
                     profile_digest
        )
                     .has_value());

        auto partial_mechanisms = receipt;
        partial_mechanisms.mechanisms.disk = glove::container::enforcement_mechanism::unavailable;
        REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                     partial_mechanisms,
                     *out->required_limits,
                     complete,
                     glove::container::sandbox_backend::linux_production,
                     profile_digest
        )
                     .has_value());

        auto invalid_termination = receipt;
        invalid_termination.termination_cause =
            glove::container::resource_termination_cause::wall_time_limit;
        REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                     invalid_termination,
                     *out->required_limits,
                     complete,
                     glove::container::sandbox_backend::linux_production,
                     profile_digest
        )
                     .has_value());

        auto remote_claim = receipt;
        remote_claim.backend = glove::container::sandbox_backend::remote_linux_container;
        remote_claim.backend_id = "remote-linux-container:trusted-operator-v1";
        remote_claim.observation_authority =
            glove::container::receipt_observation_authority::trusted_remote_claim;
        remote_claim.independently_verified = false;
        REQUIRE(!glove::container::validate_resource_enforcement_receipt(
                     remote_claim,
                     *out->required_limits,
                     complete,
                     glove::container::sandbox_backend::remote_linux_container,
                     profile_digest
        )
                     .has_value());
        REQUIRE(
            glove::container::validate_trusted_remote_resource_claim(
                remote_claim, *out->required_limits, profile_digest
            )
                .has_value()
        );
        auto lying_authority = remote_claim;
        lying_authority.observation_authority =
            glove::container::receipt_observation_authority::local_enforcement;
        REQUIRE(!glove::container::validate_trusted_remote_resource_claim(
                     lying_authority, *out->required_limits, profile_digest
        )
                     .has_value());
        auto lying_verification = remote_claim;
        lying_verification.independently_verified = true;
        REQUIRE(!glove::container::validate_trusted_remote_resource_claim(
                     lying_verification, *out->required_limits, profile_digest
        )
                     .has_value());
        auto retained_remote = remote_claim;
        retained_remote.retained_changes.push_back({});
        REQUIRE(!glove::container::validate_trusted_remote_resource_claim(
                     retained_remote, *out->required_limits, profile_digest
        )
                     .has_value());
    }

    {
        glove::container::profile p;
        p.required_limits = glove::container::resource_limits{
            .cpu_time_ms = 1,
            .memory_bytes = 0,
            .pids = 1,
            .wall_time_ms = 1,
            .disk_bytes = 1,
            .terminal_output_bytes = 1,
        };
        auto out = glove::container::validate(p);
        REQUIRE(!out.has_value());
        REQUIRE(out.error().find("non-zero") != std::string::npos);
    }

    {
        glove::container::profile p;
        p.filesystem.push_back({.path = "relative/path"});
        auto out = glove::container::validate(p);
        REQUIRE(!out.has_value());
        REQUIRE(out.error().find("absolute") != std::string::npos);
    }

    {
        glove::container::profile p;
        p.filesystem.push_back({.path = "/", .writable = true});
        auto out = glove::container::validate(p);
        REQUIRE(!out.has_value());
        REQUIRE(out.error().find("root") != std::string::npos);
    }

    {
        glove::container::profile p;
        p.filesystem.push_back({.path = "/agent/workspace"});
        p.filesystem.push_back({.path = "/agent/workspace/../workspace"});
        auto out = glove::container::validate(p);
        REQUIRE(!out.has_value());
        REQUIRE(out.error().find("duplicate") != std::string::npos);
    }

    {
        glove::container::profile p;
        p.environment = {"TOKEN=one", "TOKEN=two"};
        auto out = glove::container::validate(p);
        REQUIRE(!out.has_value());
        REQUIRE(out.error().find("duplicate environment") != std::string::npos);
    }

    {
        glove::container::profile p;
        p.filesystem.push_back({.path = ""});
        auto out = glove::container::validate(p);
        REQUIRE(!out.has_value());
        REQUIRE(out.error().find("empty path") != std::string::npos);
    }

    {
        const char* home = std::getenv("HOME");
        REQUIRE(home != nullptr && *home != '\0');
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path tmp = fs::path{home} / (".glove_t003_" + std::to_string(::getpid()));
        fs::create_directories(tmp / "real", ec);
        REQUIRE(!ec);
        fs::create_directory_symlink("real", tmp / "link", ec);
        REQUIRE(!ec);
        const std::string real = fs::weakly_canonical(tmp / "real", ec).string();
        {
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "link").string()});
            auto out = glove::container::validate(p);
            REQUIRE(out.has_value());
            REQUIRE(out->filesystem.at(0).path == real);
            REQUIRE(
                std::ranges::find(out->link_spellings, (tmp / "link").string()) !=
                out->link_spellings.end()
            );
        }
        {
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "real").string()});
            auto out = glove::container::validate(p);
            REQUIRE(out.has_value());
            REQUIRE(out->link_spellings.empty());
        }
        fs::remove_all(tmp, ec);
    }

    {
        const char* home = std::getenv("HOME");
        REQUIRE(home != nullptr && *home != '\0');
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path tmp = fs::path{home} / (".glove_t003b_" + std::to_string(::getpid()));
        fs::create_directories(tmp / "real", ec);
        REQUIRE(!ec);
        glove::container::profile p;
        p.filesystem.push_back({.path = (tmp / "real").string()});
        p.link_spellings = {"/etc/injected"};
        auto out = glove::container::validate(p);
        REQUIRE(out.has_value());
        REQUIRE(
            std::ranges::find(out->link_spellings, std::string{"/etc/injected"}) ==
            out->link_spellings.end()
        );
        fs::remove_all(tmp, ec);
    }

    {
        const char* home = std::getenv("HOME");
        REQUIRE(home != nullptr && *home != '\0');
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path tmp = fs::path{home} / (".glove_t008_" + std::to_string(::getpid()));
        fs::create_directories(tmp / "real" / "sub", ec);
        REQUIRE(!ec);
        fs::create_directory_symlink("real", tmp / "link", ec);
        REQUIRE(!ec);
        fs::create_directory_symlink("hop2", tmp / "hop1", ec);
        REQUIRE(!ec);
        fs::create_directory_symlink("real", tmp / "hop2", ec);
        REQUIRE(!ec);
        fs::create_directory_symlink("/etc", tmp / "evil", ec);
        REQUIRE(!ec);
        const auto has = [](const glove::container::profile& pr, const std::string& s) {
            return std::ranges::find(pr.link_spellings, s) != pr.link_spellings.end();
        };
        const auto sorted = [](std::vector<std::string> v) {
            std::ranges::sort(v);
            return v;
        };
        {
            // a. grant link; revalidation keeps the spelling
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "link").string()});
            auto v1 = glove::container::validate(p);
            REQUIRE(v1.has_value());
            auto v2 = glove::container::validate(*v1);
            REQUIRE(v2.has_value());
            REQUIRE(has(*v2, (tmp / "link").string()));
            // d. idempotence
            auto v3 = glove::container::validate(*v2);
            REQUIRE(v3.has_value());
            REQUIRE(sorted(v3->link_spellings) == sorted(v2->link_spellings));
        }
        {
            // b. two-hop chain
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "hop1").string()});
            auto v1 = glove::container::validate(p);
            REQUIRE(v1.has_value());
            auto v2 = glove::container::validate(*v1);
            REQUIRE(v2.has_value());
            REQUIRE(has(*v2, (tmp / "hop1").string()));
            REQUIRE(has(*v2, (tmp / "hop2").string()));
        }
        {
            // c. link is a prefix component of the grant
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "link" / "sub").string()});
            auto v1 = glove::container::validate(p);
            REQUIRE(v1.has_value());
            auto v2 = glove::container::validate(*v1);
            REQUIRE(v2.has_value());
            REQUIRE(has(*v2, (tmp / "link").string()));
        }
        {
            // e. injected spellings are still refused
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "real").string()});
            p.link_spellings = {"/etc/injected", (tmp / "evil").string()};
            auto out = glove::container::validate(p);
            REQUIRE(out.has_value());
            REQUIRE(!has(*out, "/etc/injected"));
            REQUIRE(!has(*out, (tmp / "evil").string()));
        }
        {
            // f. a supplied spelling that resolves inside the grant is kept
            glove::container::profile p;
            p.filesystem.push_back({.path = (tmp / "real").string()});
            p.link_spellings = {(tmp / "link").string()};
            auto out = glove::container::validate(p);
            REQUIRE(out.has_value());
            REQUIRE(has(*out, (tmp / "link").string()));
        }
        fs::remove_all(tmp, ec);
    }

    // Host system services come from a vetted catalog: known names validate
    // (sorted, deduplicated); unknown, raw, empty and oversized names refuse.
    {
        glove::container::profile p;
        p.system_services = {"tls-config", "network-config", "tls-config"};
        auto out = glove::container::validate(p);
        REQUIRE(out.has_value());
        REQUIRE(out->system_services == (std::vector<std::string>{"network-config", "tls-config"}));

        glove::container::profile none;
        auto empty = glove::container::validate(none);
        REQUIRE(empty.has_value());
        REQUIRE(empty->system_services.empty());

        p.system_services = {"no-such-service"};
        auto unknown = glove::container::validate(p);
        REQUIRE(!unknown.has_value());
        REQUIRE(unknown.error().contains("unknown system service 'no-such-service'"));

        p.system_services = {"com.apple.SystemConfiguration.configd"};
        auto raw = glove::container::validate(p);
        REQUIRE(!raw.has_value());
        REQUIRE(raw.error().contains("raw mach service names are not accepted"));

        p.system_services = {""};
        REQUIRE(!glove::container::validate(p).has_value());

        p.system_services = {std::string(65, 'a')};
        REQUIRE(!glove::container::validate(p).has_value());

        // One bad name refuses the whole list, even next to a good one.
        p.system_services = {"network-config", "bogus"};
        REQUIRE(!glove::container::validate(p).has_value());
    }

    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
