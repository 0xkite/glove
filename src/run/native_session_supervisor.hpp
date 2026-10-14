#pragma once

#include "glove/audit/sink.hpp"
#include "glove/host/config.hpp"

#include "native_harness_adapter.hpp"
#include "native_launch.hpp"
#include "native_management_transport.hpp"
#include "native_session_model.hpp"
#include "native_session_store.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace glove::run::detail {

// Compiled trusted composition of one harness for the supervisor. It supplies
// closed policy/encoding, the generation-local history location, the history
// validator and the host admission callbacks of the launch core. It owns no
// process, endpoint, credential or cleanup authority itself.
class native_session_harness {
public:
    virtual ~native_session_harness() = default;
    [[nodiscard]] virtual auto harness_id() const -> std::string_view = 0;
    [[nodiscard]] virtual auto history_format() const -> std::string_view = 0;
    [[nodiscard]] virtual auto policy() const -> const native_startup_policy& = 0;
    [[nodiscard]] virtual auto adapter() const -> const native_harness_adapter& = 0;
    // Leaf components below the private agent directory: directories then
    // the history file name. Bounded, no '/', '.' or '..' components.
    [[nodiscard]] virtual auto
    history_location(std::string_view workspace, std::string_view conversation_id) const
        -> std::expected<std::vector<std::string>, std::string> = 0;
    [[nodiscard]] virtual auto validator(std::string_view conversation_id) const
        -> history_validator = 0;
    // Fills admit_runtime/admit_assets/revalidate/credential/start_endpoint/
    // execute_owned. The supervisor owns every other context field.
    [[nodiscard]] virtual auto compose(native_launch_context& context)
        -> std::expected<void, std::string> = 0;
};

struct native_session_supervisor_options {
    host::directories directories;
    std::vector<std::filesystem::path> protected_auth_roots;
    std::filesystem::path workspace;
    std::filesystem::path sessions_parent;
    // Open an existing logical session; otherwise create one for conversation_id.
    std::optional<std::string> session;
    std::string runtime_digest;
    std::string model;
    net::endpoint_provider provider = net::endpoint_provider::anthropic;
    std::string conversation_id;
    std::string display_name = "native";
    std::shared_ptr<audit::sink> audit;
    std::function<void(std::string_view)> log;
};

struct supervisor_snapshot {
    std::string session;
    std::string epoch;
    session_projection projection;
    std::uint64_t launches = 0;
    // True while the synchronous generation call has not returned, including
    // retained finalization, quiescent marking and disposable-state cleanup.
    bool generation_active = false;
    std::optional<std::string> last_error;
};

class native_session_supervisor {
public:
    native_session_supervisor(const native_session_supervisor&) = delete;
    auto operator=(const native_session_supervisor&) -> native_session_supervisor& = delete;
    ~native_session_supervisor();

    // Takes the exclusive session lease, mints the epoch, reconstructs the
    // durable projection and starts the protected management listener.
    [[nodiscard]] static auto
    create(native_session_supervisor_options options, native_session_harness& harness)
        -> std::expected<std::unique_ptr<native_session_supervisor>, std::string>;

    // Runs successive synchronous generations on the calling thread until a
    // shutdown operation is admitted. Returns the number of generations run.
    [[nodiscard]] auto run() -> std::expected<std::uint64_t, std::string>;

    // Same admission path as the management transport, for host-local callers.
    [[nodiscard]] auto submit(const management_request& request) -> operation_result;

    [[nodiscard]] auto snapshot() const -> supervisor_snapshot;
    [[nodiscard]] auto control_directory() const -> std::filesystem::path;
    [[nodiscard]] auto session_root() const -> std::filesystem::path;
    [[nodiscard]] auto wait_for(
        const std::function<bool(const supervisor_snapshot&)>& predicate,
        std::chrono::milliseconds limit
    ) const -> bool;
    [[nodiscard]] auto journal() const -> std::vector<journal_event>;
    [[nodiscard]] auto management() const -> const native_management_server&;

    // Test-only persistence fault for the next publication; production never sets it.
    void inject_store_fault(store_fault fault);

private:
    struct implementation;
    explicit native_session_supervisor(std::unique_ptr<implementation> state) noexcept;
    std::unique_ptr<implementation> state_;
};

} // namespace glove::run::detail
