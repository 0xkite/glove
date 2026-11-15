#pragma once

#include "glove/host/config.hpp"
#include "glove/run/pi_launch.hpp"

#include <sys/stat.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace glove::run::admission_test_support {

namespace fs = std::filesystem;
using launch_result = std::expected<int, std::string>;

#define GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(condition)                                              \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #condition, __FILE__, __LINE__);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

inline auto private_directory(const fs::path& path) -> bool {
    fs::create_directories(path);
    return ::chmod(path.c_str(), 0700) == 0;
}

inline auto write_file(const fs::path& path, std::string_view bytes, mode_t mode = 0600) -> bool {
    std::ofstream stream{path, std::ios::binary};
    stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    stream.close();
    return stream.good() && ::chmod(path.c_str(), mode) == 0;
}

inline auto contents(const fs::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

using environment_entries = std::vector<std::pair<std::string, std::optional<std::string>>>;

class environment_scope {
public:
    explicit environment_scope(const environment_entries& values) {
        // Finish every C++ allocation before changing process-wide state. If
        // snapshot construction throws, no environment rollback is needed.
        saved_.reserve(values.size());
        for (const auto& [name, value] : values) {
            (void)value;
            const char* previous = std::getenv(name.c_str());
            saved_.emplace_back(
                name, previous ? std::optional<std::string>{previous} : std::nullopt
            );
        }
        for (const auto& [name, value] : values) {
            ok_ = (value ? ::setenv(name.c_str(), value->c_str(), 1) : ::unsetenv(name.c_str())) ==
                      0 &&
                  ok_;
        }
    }

    environment_scope(const environment_scope&) = delete;
    auto operator=(const environment_scope&) -> environment_scope& = delete;

    ~environment_scope() { (void)restore(); }

    auto ok() const -> bool { return ok_; }

    auto restore() -> bool {
        if (restored_) {
            return restore_ok_;
        }
        restored_ = true;
        for (const auto& [name, value] : saved_) {
            const bool changed =
                (value ? ::setenv(name.c_str(), value->c_str(), 1) : ::unsetenv(name.c_str())) == 0;
            const char* now = std::getenv(name.c_str());
            const bool equal = value ? now != nullptr && *value == now : now == nullptr;
            restore_ok_ = changed && equal && restore_ok_;
        }
        return restore_ok_;
    }

private:
    environment_entries saved_;
    bool ok_ = true;
    bool restored_ = false;
    bool restore_ok_ = true;
};

struct public_fixture {
    fs::path root;
    glove::host::directories dirs;
    environment_entries environment;

    auto config_path() const -> fs::path { return glove::host::default_config_path(dirs); }

    auto request() const -> glove::run::pi_launch_request {
        return {.selection = {}, .workspace = root / "workspace"};
    }

    auto prepare() -> int {
        GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(private_directory(root));
        const std::array<std::pair<const char*, const char*>, 7> names{
            {{"HOME", "home"},
             {"XDG_CONFIG_HOME", "xdg-config"},
             {"XDG_STATE_HOME", "xdg-state"},
             {"XDG_DATA_HOME", "xdg-data"},
             {"XDG_CACHE_HOME", "xdg-cache"},
             {"XDG_RUNTIME_DIR", "xdg-runtime"},
             {"TMPDIR", "tmp"}}
        };
        for (const auto& [name, component] : names) {
            GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(private_directory(root / component));
            environment.emplace_back(name, (root / component).string());
        }
        // No public case needs credentials. Restore their original values too,
        // without logging them, even when they were explicitly empty.
        environment.emplace_back("OPENAI_API_KEY", std::nullopt);
        environment.emplace_back("ANTHROPIC_API_KEY", std::nullopt);
        glove::host::environment values{
            .home = (root / "home").string(),
            .xdg_config_home = (root / "xdg-config").string(),
            .xdg_state_home = (root / "xdg-state").string(),
            .xdg_data_home = (root / "xdg-data").string(),
            .xdg_cache_home = (root / "xdg-cache").string(),
            .xdg_runtime_dir = (root / "xdg-runtime").string(),
            .temporary_directory = (root / "tmp").string()
        };
        auto resolved = glove::host::resolve_directories(values);
        GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(resolved);
        dirs = *resolved;
        for (const auto& path :
             {dirs.config,
              dirs.state,
              dirs.data,
              dirs.cache,
              dirs.runtime,
              root / "workspace",
              root / "external/keys"}) {
            GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(private_directory(path));
        }
        glove::host::config config;
        config.runtime_directory = root / "external/control";
        config.audit_key = root / "external/keys/audit.key";
        config.receipt_journal = root / "external/journals/receipts.jsonl";
        auto encoded = glove::host::encode_config(config);
        GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(encoded);
        GLOVE_PI_ADMISSION_FIXTURE_REQUIRE(write_file(config_path(), *encoded));
        return 0;
    }

    auto launch() const -> launch_result {
        environment_scope scoped{environment};
        if (!scoped.ok()) {
            throw std::runtime_error{"fixture environment installation failed"};
        }
        auto result = glove::run::launch_pi(request());
        if (!scoped.restore()) {
            throw std::runtime_error{"fixture environment restoration failed"};
        }
        return result;
    }
};

#undef GLOVE_PI_ADMISSION_FIXTURE_REQUIRE

} // namespace glove::run::admission_test_support
