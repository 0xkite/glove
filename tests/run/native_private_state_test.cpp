#include "native_harness_adapter.hpp"
#include "native_private_state.hpp"

#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
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
using namespace glove::run::detail;

struct temporary_directory {
    fs::path path;

    temporary_directory() {
        char pattern[] = "/tmp/glove-native-private-XXXXXX";
        if (const auto* created = ::mkdtemp(pattern)) {
            std::error_code error;
            path = fs::canonical(created, error);
            if (error) {
                path.clear();
            }
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        // This test never starts a child. Only its own mkdtemp tree is swept;
        // native cleanup/recovery refusals are asserted before fixture teardown.
        if (!path.empty()) {
            std::error_code error;
            fs::remove_all(path, error);
        }
    }
};

auto read_bytes(const fs::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

auto generic_payload_case() -> int {
    temporary_directory parent;
    REQUIRE(!parent.path.empty());
    auto plan = prepare_native_private_run(parent.path);
    REQUIRE(plan);
    const std::vector<native_configuration_file> files{
        {.name = "native.json", .bytes = "{\"fixture\":true}"},
        {.name = "preferences.txt", .bytes = "opaque storage fixture\n"}
    };
    auto state = native_private_state::create(*plan, files);
    REQUIRE(state);
    REQUIRE(state->root() == parent.path / plan->name);
    REQUIRE(state->home() == plan->paths().home);
    REQUIRE(state->agent() == plan->paths().agent);
    REQUIRE(state->sessions() == plan->paths().sessions);
    REQUIRE(state->configuration_paths().size() == files.size());
    for (std::size_t index = 0; index < files.size(); ++index) {
        REQUIRE(state->configuration_paths()[index] == state->agent() / files[index].name);
        REQUIRE(read_bytes(state->configuration_paths()[index]) == files[index].bytes);
        REQUIRE(
            fs::status(state->configuration_paths()[index]).permissions() == fs::perms::owner_read
        );
    }
    REQUIRE(read_bytes(state->root() / ".glove-pi-lease").starts_with("glove-pi-private-v1\n"));
    REQUIRE(!fs::exists(state->agent() / "models.json"));
    REQUIRE(state->cleanup());
    REQUIRE(!fs::exists(parent.path / plan->name));
    return 0;
}

auto refusal_case() -> int {
    temporary_directory parent;
    REQUIRE(!parent.path.empty());
    const std::vector<native_configuration_file> valid{{.name = "native.json", .bytes = "{}"}};
    for (int mutation = 0; mutation < 5; ++mutation) {
        auto files = valid;
        switch (mutation) {
        case 0:
            files.clear();
            break;
        case 1:
            files.front().name = "../outside";
            break;
        case 2:
            files.push_back({.name = "NATIVE.JSON", .bytes = "{}"});
            break;
        case 3:
            files.front().bytes.assign(32769, 'x');
            break;
        case 4:
            files.resize(17);
            break;
        }
        REQUIRE(!native_private_state::create(parent.path, files));
        REQUIRE(fs::is_empty(parent.path));
    }
    for (const auto& spelling : {parent.path.string() + "/", parent.path.string() + "//"}) {
        REQUIRE(!prepare_native_private_run(fs::path{spelling}));
        REQUIRE(fs::is_empty(parent.path));
    }
    const auto repeated =
        parent.path.parent_path().string() + "//" + parent.path.filename().string();
    REQUIRE(!prepare_native_private_run(fs::path{repeated}));
    REQUIRE(fs::is_empty(parent.path));
    auto plan = prepare_native_private_run(parent.path);
    REQUIRE(plan);
    plan->name = "../outside";
    REQUIRE(!native_private_state::create(*plan, valid));
    REQUIRE(fs::is_empty(parent.path));
    return 0;
}

auto launching_retention_case() -> int {
    temporary_directory parent;
    REQUIRE(!parent.path.empty());
    const std::vector<native_configuration_file> files{{.name = "native.json", .bytes = "{}"}};
    fs::path root;
    {
        auto state = native_private_state::create(parent.path, files);
        REQUIRE(state);
        root = state->root();
        REQUIRE(state->mark_launching());
        REQUIRE(!state->cleanup());
    }
    REQUIRE(fs::exists(root));
    REQUIRE(!native_private_state::recover(parent.path));
    REQUIRE(fs::exists(root));
    return 0;
}

} // namespace

auto main() -> int {
    REQUIRE(generic_payload_case() == 0);
    REQUIRE(refusal_case() == 0);
    REQUIRE(launching_retention_case() == 0);
    return 0;
}
