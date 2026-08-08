#include "glove/container/receipt_producer.hpp"

#include "remote_session_runtime.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

constexpr std::string_view unavailable = "remote lifecycle is constructed but not operational";

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-remote-runtime-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
            (void)::chmod(root_.c_str(), 0700);
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

template<typename Value>
[[nodiscard]] auto denied(const std::expected<Value, std::string>& result) -> bool {
    return !result && result.error() == unavailable;
}

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto ssh_config = temporary.root() / "remote-ssh/config";
    const glove::control::remote_session_runtime_config configured{
        .ssh_argv = {"/usr/bin/ssh", "-F", ssh_config.string(), "glove-remote"},
        .executor_digest = "sha256:" + std::string(64U, 'a'),
        .container_image = "registry.example.test/glove/runtime@sha256:" + std::string(64U, 'b'),
        .container_image_digest = "sha256:" + std::string(64U, 'b'),
        .channel_timeout_ms = 5'000,
        .max_clock_skew_ms = 250,
        .max_sessions = 4,
        .staging_root = "/var/lib/glove-remote/staging",
    };
    auto runtime = glove::control::remote_session_runtime::create(configured);
    REQUIRE(runtime.has_value());
    REQUIRE((*runtime)->backend_id() == "remote_linux_container");
    REQUIRE(!(*runtime)->lifecycle_operational());
    REQUIRE((*runtime)->agent_runtime_adapter_schema_version() == 0);
    REQUIRE((*runtime)->managed_runtime_ids().empty());
    REQUIRE(!(*runtime)->resource_capabilities().complete());
    REQUIRE((*runtime)->resource_capabilities().receipt_schema_version == 0);
    REQUIRE((*runtime)->ssh_argv() == configured.ssh_argv);
    REQUIRE((*runtime)->container_image() == configured.container_image);
    REQUIRE((*runtime)->container_image_digest() == configured.container_image_digest);

    auto invalid = configured;
    invalid.ssh_argv.push_back("remote-command");
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));
    invalid = configured;
    invalid.executor_digest.clear();
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));
    invalid = configured;
    invalid.container_image =
        "registry.example.test/glove/runtime:latest@" + invalid.container_image_digest;
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));
    invalid = configured;
    invalid.container_image = "registry.example.test/glove/runtime@sha256:" + std::string(64U, 'c');
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));
    invalid = configured;
    invalid.container_image_digest = "sha256:" + std::string(64U, 'A');
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));
    invalid = configured;
    invalid.channel_timeout_ms = 0;
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));
    invalid = configured;
    invalid.staging_root = "relative";
    REQUIRE(!glove::control::remote_session_runtime::create(invalid));

    const auto key = temporary.root() / "audit.key";
    {
        std::ofstream output{key};
        output << "000102030405060708090a0b0c0d0e0f"
                  "101112131415161718191a1b1c1d1e1f\n";
    }
    REQUIRE(::chmod(key.c_str(), 0600) == 0);
    auto producer = glove::container::receipt_audit_producer::initialize({
        .key_path = key,
        .journal_path = temporary.root() / "receipts.journal",
    });
    REQUIRE(producer.has_value());

    const glove::control::session_start_authorization authorization{};
    REQUIRE(denied((*runtime)->start(**producer, authorization, "start-1", 1)));
    REQUIRE(denied((*runtime)->reconcile(**producer, 1)));
    REQUIRE(denied((*runtime)->list()));
    REQUIRE(denied((*runtime)->read("session", 0, 1)));
    REQUIRE(denied((*runtime)->wait_read("session", 0, 1, 1)));
    REQUIRE(denied((*runtime)->write_input("session", "x")));
    REQUIRE(denied((*runtime)->resize("session", 24, 80)));
    REQUIRE(denied((*runtime)->signal("session", glove::control::session_signal::terminate)));
    REQUIRE(denied((*runtime)->stop("session")));
    REQUIRE(denied((*runtime)->stop("session", "stop-1")));
    REQUIRE(denied((*runtime)->wait("session")));
    REQUIRE(denied((*runtime)->cleanup("session")));
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
