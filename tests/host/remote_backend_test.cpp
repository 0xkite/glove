#include "../../include/glove/host/config.hpp"
#include "../../include/glove/host/remote_backend.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(condition)                                                                         \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-remote-backend-test-XXXXXX";
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

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

[[nodiscard]] auto effective_ssh_config(const std::filesystem::path& config_path)
    -> std::optional<std::string> {
    std::array<int, 2> output_pipe{-1, -1};
    if (::pipe(output_pipe.data()) != 0) {
        return std::nullopt;
    }
    const auto child = ::fork();
    if (child < 0) {
        (void)::close(output_pipe[0]);
        (void)::close(output_pipe[1]);
        return std::nullopt;
    }
    if (child == 0) {
        (void)::close(output_pipe[0]);
        if (::dup2(output_pipe[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        (void)::close(output_pipe[1]);
        const int null_descriptor = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_descriptor >= 0) {
            (void)::dup2(null_descriptor, STDERR_FILENO);
            (void)::close(null_descriptor);
        }
        ::execl(
            "/usr/bin/ssh",
            "ssh",
            "-G",
            "-F",
            config_path.c_str(),
            "glove-remote",
            static_cast<char*>(nullptr)
        );
        _exit(127);
    }

    (void)::close(output_pipe[1]);
    std::string output;
    std::array<char, 4096> chunk{};
    while (true) {
        const auto count = ::read(output_pipe[0], chunk.data(), chunk.size());
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        output.append(chunk.data(), static_cast<std::size_t>(count));
    }
    (void)::close(output_pipe[0]);
    int status = 0;
    pid_t waited = -1;
    do {
        waited = ::waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::nullopt;
    }
    return output;
}

[[nodiscard]] auto has_line(std::string_view contents, std::string_view line) -> bool {
    return contents.starts_with(std::string{line} + "\n") ||
           contents.find("\n" + std::string{line} + "\n") != std::string::npos;
}

auto make_remote(const std::filesystem::path& identity) -> glove::host::remote_backend_config {
    constexpr std::string_view public_key =
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    auto fingerprint = glove::host::openssh_host_key_fingerprint(public_key);
    return {
        .host = "research.example.test",
        .user = "glove_remote",
        .port = 2222,
        .host_public_key = std::string{public_key},
        .host_key_fingerprint = fingerprint.value_or("invalid"),
        .identity_file = identity,
        .executor_digest = "sha256:" + std::string(64U, 'a'),
        .container_image = "registry.example.test/glove/runtime@sha256:" + std::string(64U, 'b'),
        .container_image_digest = "sha256:" + std::string(64U, 'b'),
        .channel_timeout_ms = 5'000,
        .max_clock_skew_ms = 250,
        .max_sessions = 4,
        .staging_root = "/var/lib/glove-remote/staging",
    };
}

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto identity = temporary.root() / "remote-identity";
    {
        std::ofstream output{identity};
        output << "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n";
    }
    REQUIRE(::chmod(identity.c_str(), 0600) == 0);

    auto remote = make_remote(identity);
    REQUIRE(remote.host_key_fingerprint.starts_with("SHA256:"));
    REQUIRE(glove::host::validate(remote).has_value());

    glove::host::config configured{
        .schema_version = 1,
        .runtime_directory = temporary.root(),
        .audit_key = temporary.root() / "audit.key",
        .receipt_journal = temporary.root() / "receipts.journal",
        .session_policy = temporary.root() / "policy.json",
        .session_store = temporary.root() / "sessions.journal",
        .remote_backend = remote,
    };
    REQUIRE(glove::host::validate(configured).has_value());
    auto encoded = glove::host::encode_config(configured);
    REQUIRE(encoded.has_value());
    REQUIRE(encoded->find("\"remote_backend\"") != std::string::npos);

    const auto config_path = temporary.root() / "config.json";
    REQUIRE(glove::host::write_config_exclusive(config_path, configured).has_value());
    REQUIRE(glove::host::load_config(config_path) == configured);

    auto artifacts = glove::host::prepare_remote_ssh_artifacts(remote, temporary.root());
    REQUIRE(artifacts.has_value());
    const std::vector<std::string> expected_argv{
        "/usr/bin/ssh", "-F", artifacts->config_path.string(), "glove-remote"
    };
    REQUIRE(artifacts->argv == expected_argv);
    const auto ssh_config = read_file(artifacts->config_path);
    REQUIRE(ssh_config.find("Host glove-remote\n") != std::string::npos);
    REQUIRE(ssh_config.find("  HostName research.example.test\n") != std::string::npos);
    REQUIRE(ssh_config.find("  User glove_remote\n") != std::string::npos);
    REQUIRE(ssh_config.find("  Port 2222\n") != std::string::npos);
    REQUIRE(ssh_config.find("  StrictHostKeyChecking yes\n") != std::string::npos);
    REQUIRE(ssh_config.find("  GlobalKnownHostsFile none\n") != std::string::npos);
    REQUIRE(ssh_config.find("  HostKeyAlgorithms ssh-ed25519\n") != std::string::npos);
    REQUIRE(ssh_config.find("  UpdateHostKeys no\n") != std::string::npos);
    REQUIRE(ssh_config.find("  IdentityAgent none\n") != std::string::npos);
    REQUIRE(ssh_config.find("  ProxyCommand none\n") != std::string::npos);
    REQUIRE(ssh_config.find("  ProxyJump none\n") != std::string::npos);
    REQUIRE(ssh_config.find("  RemoteCommand none\n") != std::string::npos);
    REQUIRE(ssh_config.find("  ControlMaster no\n") != std::string::npos);
    REQUIRE(ssh_config.find("  ControlPath none\n") != std::string::npos);
    REQUIRE(ssh_config.find("  ControlPersist no\n") != std::string::npos);
    REQUIRE(ssh_config.find("Include") == std::string::npos);
    REQUIRE(ssh_config.find("SendEnv") == std::string::npos);
    REQUIRE(ssh_config.find("SetEnv") == std::string::npos);
    auto effective = effective_ssh_config(artifacts->config_path);
    REQUIRE(effective.has_value());
    REQUIRE(has_line(*effective, "globalknownhostsfile none"));
    REQUIRE(has_line(*effective, "hostkeyalgorithms ssh-ed25519"));
    REQUIRE(has_line(*effective, "updatehostkeys false"));
    REQUIRE(
        read_file(artifacts->known_hosts_path) ==
        "[research.example.test]:2222 " + remote.host_public_key + "\n"
    );
    struct stat metadata{};
    REQUIRE(::lstat(artifacts->config_path.c_str(), &metadata) == 0);
    REQUIRE(S_ISREG(metadata.st_mode));
    REQUIRE((static_cast<unsigned int>(metadata.st_mode) & 0777U) == 0600U);
    REQUIRE(::lstat(artifacts->config_path.parent_path().c_str(), &metadata) == 0);
    REQUIRE(S_ISDIR(metadata.st_mode));
    REQUIRE((static_cast<unsigned int>(metadata.st_mode) & 0777U) == 0700U);

    auto overlap = remote;
    overlap.identity_file = artifacts->config_path;
    REQUIRE(!glove::host::prepare_remote_ssh_artifacts(overlap, temporary.root()).has_value());
    overlap.identity_file = artifacts->known_hosts_path;
    REQUIRE(!glove::host::prepare_remote_ssh_artifacts(overlap, temporary.root()).has_value());

    auto invalid = remote;
    invalid.host = "-oProxyCommand=touch /tmp/sentinel";
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.user = "operator@host";
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.port = 0;
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.host_key_fingerprint = "SHA256:wrong";
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.executor_digest = std::string(64U, 'a');
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.container_image = "registry.example.test/glove/runtime:latest";
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.container_image =
        "registry.example.test/glove/runtime:latest@" + invalid.container_image_digest;
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.container_image = "registry.example.test/glove/runtime@sha256:" + std::string(64U, 'c');
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.container_image_digest = "sha256:" + std::string(64U, 'c');
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.channel_timeout_ms = 0;
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.max_sessions = 0;
    REQUIRE(!glove::host::validate(invalid).has_value());
    invalid = remote;
    invalid.staging_root = "relative/staging";
    REQUIRE(!glove::host::validate(invalid).has_value());

    {
        std::ofstream tampered{artifacts->config_path, std::ios::trunc};
        tampered << "Host attacker-controlled\n";
        REQUIRE(tampered.good());
    }
    REQUIRE(!glove::host::prepare_remote_ssh_artifacts(remote, temporary.root()).has_value());

    REQUIRE(::chmod(identity.c_str(), 0644) == 0);
    REQUIRE(!glove::host::prepare_remote_ssh_artifacts(remote, temporary.root()).has_value());

    // A pre-remote schema-v1 configuration remains valid and decodes with the
    // new section absent.
    auto old = configured;
    old.remote_backend.reset();
    REQUIRE(std::filesystem::remove(config_path));
    REQUIRE(glove::host::write_config_exclusive(config_path, old).has_value());
    auto loaded_old = glove::host::load_config(config_path);
    REQUIRE(loaded_old.has_value());
    REQUIRE(!loaded_old->remote_backend.has_value());
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
