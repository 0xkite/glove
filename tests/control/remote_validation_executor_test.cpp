#include "glove/container/digest.hpp"
#include "glove/control/remote_protocol.hpp"
#include "glove/control/remote_validation.hpp"

#include "remote_validation_executor.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

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
        std::string pattern = "/tmp/glove-remote-validation-test-XXXXXX";
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

void write_file(const std::filesystem::path& path, std::string_view contents) {
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

[[nodiscard]] auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

[[nodiscard]] auto file_digest(const std::filesystem::path& path) -> std::string {
    const auto contents = read_file(path);
    auto digest = glove::container::sha256_hex(
        std::span<const unsigned char>{
            reinterpret_cast<const unsigned char*>(contents.data()), contents.size()
        }
    );
    return digest ? "sha256:" + *digest : std::string{};
}

[[nodiscard]] auto make_script(const temporary_directory& temporary, std::string_view executor_hex)
    -> std::filesystem::path {
    const auto script = temporary.root() / "fake-docker";
    const auto log = temporary.root() / "docker.log";
    const auto output = temporary.root() / "container-output";
    const auto slow = temporary.root() / "slow-run";
    const auto running = temporary.root() / "running";
    const auto reconcile = temporary.root() / "reconcile";
    std::string contents =
        "#!/bin/sh\n"
        "log='" +
        log.string() +
        "'\n"
        "printf 'CALL-BEGIN\\n' >> \"$log\"\n"
        "for arg in \"$@\"; do printf 'ARG=<%s>\\n' \"$arg\" >> \"$log\"; done\n"
        "printf 'ENV-BEGIN\\n' >> \"$log\"\n"
        "/usr/bin/env >> \"$log\"\n"
        "printf 'ENV-END\\nCALL-END\\n' >> \"$log\"\n"
        "case \"$1\" in\n"
        "  ps) if [ -f '" +
        reconcile.string() + "' ]; then cat '" + reconcile.string() +
        "'; fi ;;\n"
        "  inspect)\n"
        "    case \"$3\" in\n"
        "      *remote-validation*)\n"
        "        if [ \"$4\" = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "
        "]; then\n"
        "          printf '1|" +
        std::string{executor_hex} +
        "\\n'\n"
        "        else printf '0|foreign\\n'; fi ;;\n"
        "      *) if [ -f '" +
        running.string() +
        "' ]; then printf 'true 0\\n'; else printf 'false 0\\n'; fi ;;\n"
        "    esac ;;\n"
        "  run)\n"
        "    if [ -f '" +
        slow.string() +
        "' ]; then /bin/sleep 2; fi\n"
        "    : > '" +
        running.string() +
        "'\n"
        "    printf 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\n' ;;\n"
        "  logs) if [ -f '" +
        output.string() + "' ]; then cat '" + output.string() +
        "'; fi ;;\n"
        "  stop|kill|rm) rm -f '" +
        running.string() +
        "' ;;\n"
        "esac\n"
        "exit 0\n";
    write_file(script, contents);
    (void)::chmod(script.c_str(), 0500);
    return script;
}

[[nodiscard]] auto
binding(std::string session_id, std::string epoch, std::string key, std::string descriptor)
    -> glove::control::remote_operation_binding {
    return {
        .session_id = std::move(session_id),
        .session_epoch = std::move(epoch),
        .descriptor_digest = std::move(descriptor),
        .idempotency_key = std::move(key),
        .payload_digest = {},
    };
}

template<typename Payload>
[[nodiscard]] auto bound(glove::control::remote_method method, Payload payload)
    -> glove::control::remote_validation_payload {
    auto result = glove::control::bind_remote_validation_payload(
        method, glove::control::remote_validation_payload{std::move(payload)}
    );
    return result ? std::move(*result)
                  : glove::control::remote_validation_payload{
                        glove::control::remote_prepare_payload{}
                    };
}

[[nodiscard]] auto request(
    glove::control::remote_validation_executor& executor,
    std::string_view id,
    glove::control::remote_method method,
    const glove::control::remote_validation_payload& payload,
    std::uint64_t ttl_ms = 2'000
) -> std::expected<std::string, std::string> {
    auto encoded = glove::control::encode_remote_validation_request(id, method, ttl_ms, payload);
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    return executor.handle(
        *encoded, std::chrono::steady_clock::now() + std::chrono::milliseconds{ttl_ms}
    );
}

[[nodiscard]] auto
contains_call(std::string_view log, std::string_view first, std::string_view second = {}) -> bool {
    const auto first_at = log.find("ARG=<" + std::string{first} + ">");
    return first_at != std::string_view::npos &&
           (second.empty() ||
            log.find("ARG=<" + std::string{second} + ">", first_at) != std::string_view::npos);
}

} // namespace

auto main() -> int {
    using namespace glove::control;
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto staging = temporary.root() / "staging";
    REQUIRE(std::filesystem::create_directory(staging));
    REQUIRE(::chmod(staging.c_str(), 0700) == 0);
    const auto stale_stage = staging / ("s-" + std::string(32U, '0'));
    const auto foreign_stage = staging / "operator-data";
    REQUIRE(std::filesystem::create_directory(stale_stage));
    REQUIRE(std::filesystem::create_directory(foreign_stage));

    const std::string executor_digest = "sha256:" + std::string(64U, 'e');
    const std::string descriptor_digest = "sha256:" + std::string(64U, 'd');
    const auto fake_docker = make_script(temporary, executor_digest.substr(7));
    const auto docker_log = temporary.root() / "docker.log";
    const auto reconcile = temporary.root() / "reconcile";
    write_file(
        reconcile,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    );

    remote_validation_executor_config configured{
        .executor_digest = executor_digest,
        .container_image = "registry.example.test/glove/workerd@sha256:" + std::string(64U, 'a'),
        .container_image_digest = "sha256:" + std::string(64U, 'a'),
        .workerd_digest = "sha256:" + std::string(64U, 'b'),
        .descriptor_digest = descriptor_digest,
        .staging_root = staging,
        .max_sessions = 4,
        .max_ttl_ms = 250,
        .docker_executable = fake_docker,
        .docker_executable_digest = file_digest(fake_docker),
    };
    REQUIRE(::setenv("GLOVE_REMOTE_ENV_INJECTION", "must-not-cross", 1) == 0);
    auto executor = remote_validation_executor::create_for_testing(configured);
    REQUIRE(executor.has_value());
    REQUIRE(!std::filesystem::exists(stale_stage));
    REQUIRE(std::filesystem::is_directory(foreign_stage));

    auto startup_log = read_file(docker_log);
    REQUIRE(contains_call(startup_log, "ps", "label=io.sage.glove.remote-validation=1"));
    REQUIRE(contains_call(startup_log, "kill", std::string(64U, 'a')));
    REQUIRE(contains_call(startup_log, "rm", std::string(64U, 'a')));
    REQUIRE(
        startup_log.find("ARG=<kill>\nARG=<" + std::string(64U, 'b') + ">") == std::string::npos
    );
    REQUIRE(
        startup_log.find("ARG=<rm>\nARG=<-f>\nARG=<" + std::string(64U, 'b') + ">") ==
        std::string::npos
    );
    write_file(docker_log, {});
    std::filesystem::remove(reconcile);

    auto health_frame = encode_remote_request("health", remote_method::remote_health, 1'000);
    REQUIRE(health_frame.has_value());
    auto health_reply = (*executor)->handle(
        *health_frame, std::chrono::steady_clock::now() + std::chrono::seconds{1}
    );
    REQUIRE(health_reply.has_value());
    auto health = decode_remote_response(*health_reply);
    REQUIRE(health.has_value());
    REQUIRE(health->status == "validation_only");
    REQUIRE(health->validation_only);
    REQUIRE(health->validation_schema_version == 1);
    REQUIRE(!health->lifecycle_operational);
    REQUIRE(health->descriptor_digest == descriptor_digest);

    auto input_frame = encode_remote_request("input", remote_method::remote_write_input, 1'000);
    REQUIRE(input_frame.has_value());
    auto input_reply = (*executor)->handle(
        *input_frame, std::chrono::steady_clock::now() + std::chrono::seconds{1}
    );
    REQUIRE(input_reply.has_value());
    auto input_denial = decode_remote_response(*input_reply);
    REQUIRE(input_denial.has_value());
    REQUIRE(input_denial->error_code == "method_not_found");

    constexpr std::string_view epoch = "00112233445566778899aabbccddeeff";
    auto prepare = bound(
        remote_method::remote_prepare,
        remote_prepare_payload{
            .binding = binding("session-one", std::string{epoch}, "prepare-1", descriptor_digest)
        }
    );
    auto prepared_reply = request(**executor, "prepare", remote_method::remote_prepare, prepare);
    REQUIRE(prepared_reply.has_value());
    auto prepared = decode_remote_validation_result(*prepared_reply);
    REQUIRE(prepared.has_value());
    REQUIRE(prepared->state == "prepared");
    auto replay = request(**executor, "prepare", remote_method::remote_prepare, prepare);
    REQUIRE(replay == prepared_reply);
    auto replay_with_new_id =
        request(**executor, "prepare-retry", remote_method::remote_prepare, prepare);
    REQUIRE(replay_with_new_id.has_value());
    REQUIRE(replay_with_new_id->find("\"id\":\"prepare-retry\"") != std::string::npos);

    auto conflicting = bound(
        remote_method::remote_start,
        remote_start_payload{
            .binding = binding("session-one", std::string{epoch}, "prepare-1", descriptor_digest)
        }
    );
    auto conflict_reply = request(**executor, "conflict", remote_method::remote_start, conflicting);
    REQUIRE(conflict_reply.has_value());
    auto conflict = decode_remote_validation_result(*conflict_reply);
    REQUIRE(!conflict.has_value());
    REQUIRE(conflict.error() == "idempotency_conflict");

    auto start = bound(
        remote_method::remote_start,
        remote_start_payload{
            .binding = binding("session-one", std::string{epoch}, "start-1", descriptor_digest)
        }
    );
    auto started_reply = request(**executor, "start", remote_method::remote_start, start);
    REQUIRE(started_reply.has_value());
    auto started = decode_remote_validation_result(*started_reply);
    REQUIRE(started.has_value());
    REQUIRE(started->state == "running");

    const auto launch_log = read_file(docker_log);
    for (const std::string_view required : {
             "ARG=<run>",
             "ARG=<--pull>",
             "ARG=<never>",
             "ARG=<--read-only>",
             "ARG=<--network>",
             "ARG=<none>",
             "ARG=<--cap-drop>",
             "ARG=<ALL>",
             "ARG=<no-new-privileges:true>",
             "ARG=<65532:65532>",
             "ARG=<--memory>",
             "ARG=<--pids-limit>",
             "ARG=<--cpus>",
             "ARG=<--tmpfs>",
             "ARG=<--log-driver>",
             "ARG=<local>",
             "ARG=<max-size=64k>",
             "ARG=<max-file=1>",
             "ARG=<--entrypoint>",
             "ARG=</opt/glove/bin/validate-workerd>",
         }) {
        REQUIRE(launch_log.find(required) != std::string::npos);
    }
    REQUIRE(launch_log.find("ARG=<--volume>") == std::string::npos);
    REQUIRE(launch_log.find("ARG=<-v>") == std::string::npos);
    REQUIRE(launch_log.find("ARG=<--env>") == std::string::npos);
    REQUIRE(launch_log.find("ARG=<-e>") == std::string::npos);
    REQUIRE(launch_log.find("GLOVE_REMOTE_ENV_INJECTION") == std::string::npos);
    REQUIRE(launch_log.find("HOME=") == std::string::npos);
    REQUIRE(launch_log.find("DOCKER_CONFIG=") == std::string::npos);
    REQUIRE(launch_log.find(configured.container_image) != std::string::npos);

    write_file(temporary.root() / "container-output", "validator-ok\n");
    auto read_payload = bound(
        remote_method::remote_read,
        remote_read_payload{
            .binding = binding("session-one", std::string{epoch}, "read-1", descriptor_digest),
            .cursor = 0,
            .max_bytes = 64,
        }
    );
    auto read_reply = request(**executor, "read", remote_method::remote_read, read_payload);
    REQUIRE(read_reply.has_value());
    auto read = decode_remote_validation_result(*read_reply);
    REQUIRE(read.has_value());
    REQUIRE(read->bytes == "validator-ok\n");

    auto cleanup_payload = bound(
        remote_method::remote_cleanup,
        remote_cleanup_payload{
            .binding = binding("session-one", std::string{epoch}, "cleanup-1", descriptor_digest)
        }
    );
    auto cleanup_reply =
        request(**executor, "cleanup", remote_method::remote_cleanup, cleanup_payload);
    REQUIRE(cleanup_reply.has_value());
    auto cleaned = decode_remote_validation_result(*cleanup_reply);
    REQUIRE(cleaned.has_value());
    REQUIRE(cleaned->state == "cleaned");
    auto cleanup_replay =
        request(**executor, "cleanup", remote_method::remote_cleanup, cleanup_payload);
    REQUIRE(cleanup_replay == cleanup_reply);

    // The binding grammar rejects option/shell/path injection before Docker.
    auto injected = bind_remote_validation_payload(
        remote_method::remote_prepare,
        remote_validation_payload{remote_prepare_payload{
            .binding =
                binding("--name;touch/tmp/pwn", std::string{epoch}, "inject", descriptor_digest),
        }}
    );
    REQUIRE(!injected.has_value());
    auto invalid_config = configured;
    invalid_config.container_image =
        "registry.example.test/x@sha256:" + std::string(64U, 'a') + " --volume=/:/host";
    REQUIRE(!remote_validation_executor::create_for_testing(invalid_config).has_value());

    // A child that exceeds the request deadline is killed and receives rm -f cleanup.
    write_file(temporary.root() / "slow-run", "1");
    auto slow_prepare = bound(
        remote_method::remote_prepare,
        remote_prepare_payload{
            .binding =
                binding("slow", "11112222333344445555666677778888", "slow-p", descriptor_digest)
        }
    );
    REQUIRE(request(**executor, "slow-p", remote_method::remote_prepare, slow_prepare).has_value());
    auto slow_start = bound(
        remote_method::remote_start,
        remote_start_payload{
            .binding =
                binding("slow", "11112222333344445555666677778888", "slow-s", descriptor_digest)
        }
    );
    auto slow_reply = request(**executor, "slow-s", remote_method::remote_start, slow_start, 100);
    REQUIRE(slow_reply.has_value());
    auto slow_error = decode_remote_validation_result(*slow_reply);
    REQUIRE(!slow_error.has_value());
    REQUIRE(slow_error.error() == "docker_failure");
    std::filesystem::remove(temporary.root() / "slow-run");
    REQUIRE(contains_call(read_file(docker_log), "rm", "-f"));

    // Output is aggregate-capped before a read result can allocate or return it.
    auto cap_prepare = bound(
        remote_method::remote_prepare,
        remote_prepare_payload{
            .binding =
                binding("cap", "22223333444455556666777788889999", "cap-p", descriptor_digest)
        }
    );
    REQUIRE(request(**executor, "cap-p", remote_method::remote_prepare, cap_prepare).has_value());
    auto cap_start = bound(
        remote_method::remote_start,
        remote_start_payload{
            .binding =
                binding("cap", "22223333444455556666777788889999", "cap-s", descriptor_digest)
        }
    );
    REQUIRE(request(**executor, "cap-s", remote_method::remote_start, cap_start).has_value());
    write_file(
        temporary.root() / "container-output",
        std::string(max_remote_validation_output_bytes + 1U, 'x')
    );
    auto cap_read = bound(
        remote_method::remote_read,
        remote_read_payload{
            .binding =
                binding("cap", "22223333444455556666777788889999", "cap-r", descriptor_digest),
            .cursor = 0,
            .max_bytes = 16,
        }
    );
    auto capped_reply = request(**executor, "cap-r", remote_method::remote_read, cap_read);
    REQUIRE(capped_reply.has_value());
    auto capped = decode_remote_validation_result(*capped_reply);
    REQUIRE(!capped.has_value());
    REQUIRE(capped.error() == "output_limit");

    // A live owner disconnect always performs stop, kill, and rm -f.
    write_file(temporary.root() / "container-output", {});
    auto disconnect_prepare = bound(
        remote_method::remote_prepare,
        remote_prepare_payload{
            .binding = binding(
                "disconnect", "3333444455556666777788889999aaaa", "disc-p", descriptor_digest
            )
        }
    );
    REQUIRE(
        request(**executor, "disc-p", remote_method::remote_prepare, disconnect_prepare).has_value()
    );
    auto disconnect_start = bound(
        remote_method::remote_start,
        remote_start_payload{
            .binding = binding(
                "disconnect", "3333444455556666777788889999aaaa", "disc-s", descriptor_digest
            )
        }
    );
    REQUIRE(
        request(**executor, "disc-s", remote_method::remote_start, disconnect_start).has_value()
    );
    write_file(docker_log, {});
    (*executor)->disconnect_cleanup();
    const auto disconnect_log = read_file(docker_log);
    REQUIRE(contains_call(disconnect_log, "stop", "--time"));
    REQUIRE(contains_call(disconnect_log, "kill"));
    REQUIRE(contains_call(disconnect_log, "rm", "-f"));

    // The watchdog enforces the configured lifetime without a follow-up request.
    auto watchdog_prepare = bound(
        remote_method::remote_prepare,
        remote_prepare_payload{
            .binding =
                binding("watchdog", "444455556666777788889999aaaabbbb", "wd-p", descriptor_digest)
        }
    );
    REQUIRE(
        request(**executor, "wd-p", remote_method::remote_prepare, watchdog_prepare).has_value()
    );
    auto watchdog_start = bound(
        remote_method::remote_start,
        remote_start_payload{
            .binding =
                binding("watchdog", "444455556666777788889999aaaabbbb", "wd-s", descriptor_digest)
        }
    );
    REQUIRE(
        request(**executor, "wd-s", remote_method::remote_start, watchdog_start, 2'000).has_value()
    );
    write_file(docker_log, {});
    std::this_thread::sleep_for(std::chrono::milliseconds{400});
    REQUIRE(contains_call(read_file(docker_log), "rm", "-f"));

    // Public managed-session runtime capabilities remain non-advertised in the
    // separate remote_session_runtime test; this health surface says so too.
    REQUIRE(!health->lifecycle_operational);
    return 0;
}
