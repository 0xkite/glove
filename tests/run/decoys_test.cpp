// Decoys are planted all-or-nothing as new owner-only canary files, never
// inside a grant, never over an existing file, never in a directory the user
// does not control; they are removed only while their content is still the
// canary; and a later launch removes what a launch without its journal lock
// left behind.

#include "decoys.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

using glove::run::detail::decoy_set;

class temporary_tree {
public:
    temporary_tree() {
        std::error_code ec;
        const auto base = std::filesystem::canonical(std::filesystem::temp_directory_path(), ec);
        std::string pattern = (base / "glove_decoys_test_XXXXXX").string();
        if (!ec && ::mkdtemp(pattern.data()) != nullptr) {
            path_ = pattern;
        }
    }

    temporary_tree(const temporary_tree&) = delete;
    auto operator=(const temporary_tree&) -> temporary_tree& = delete;
    temporary_tree(temporary_tree&&) = delete;
    auto operator=(temporary_tree&&) -> temporary_tree& = delete;

    ~temporary_tree() {
        if (!path_.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }
    }

    [[nodiscard]] auto path() const -> const std::filesystem::path& { return path_; }

private:
    std::filesystem::path path_;
};

auto read_file(const std::filesystem::path& path) -> std::string {
    std::ifstream stream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

auto mode_of(const std::filesystem::path& path) -> unsigned {
    struct stat metadata{};
    return ::lstat(path.c_str(), &metadata) == 0 ? metadata.st_mode & 07777U : 0U;
}

auto journal_count(const std::filesystem::path& journal) -> std::size_t {
    std::size_t count = 0;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(journal, ec)) {
        count += entry.path().filename().string().starts_with("launch-") ? 1U : 0U;
    }
    return count;
}

auto private_directory(const std::filesystem::path& path) -> bool {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    std::filesystem::permissions(path, std::filesystem::perms::owner_all, ec);
    return !ec;
}

auto plants_and_removes(const std::filesystem::path& root) -> int {
    const auto vault = root / "home" / "vault";
    const auto journal = root / "journal";
    REQUIRE(private_directory(root / "home") && private_directory(vault));
    REQUIRE(private_directory(journal));
    const std::vector<std::string> templates{
        (vault / "canary_{nonce}").string(),
        (vault / "note_{nonce}").string(),
        (vault / "third_{nonce}").string(),
    };
    const std::vector<std::string> exposed{(root / "workspace").string()};
    auto planted = decoy_set::plant(templates, exposed, journal);
    if (!planted) {
        std::fprintf(stderr, "%s\n", planted.error().c_str());
    }
    REQUIRE(planted.has_value());
    REQUIRE(planted->paths().size() == 3);
    const auto first = planted->paths()[0].filename().string();
    const auto second = planted->paths()[1].filename().string();
    REQUIRE(!first.contains("{nonce}") && first.starts_with("canary_"));
    // One nonce per launch.
    REQUIRE(first.substr(7) == second.substr(5));
    for (const auto& path : planted->paths()) {
        REQUIRE(mode_of(path) == 0600U);
        const auto text = read_file(path);
        REQUIRE(text.starts_with("glvc_") && text.size() == 5 + 26 + 1);
    }
    REQUIRE(read_file(planted->paths()[0]) != read_file(planted->paths()[1]));
    REQUIRE(journal_count(journal) == 1);

    // A live launch's journal is locked, so a sweep leaves its decoys.
    REQUIRE(glove::run::detail::sweep_stale_decoys(journal) == 0);
    REQUIRE(std::filesystem::exists(planted->paths()[0]));

    // A decoy whose content changed is no longer ours and stays.
    const auto changed = planted->paths()[1];
    {
        std::ofstream rewrite{changed, std::ios::trunc};
        rewrite << "someone else's file\n";
    }
    std::error_code ec;
    // Also when the replacement is another canary of the same length.
    const auto swapped = planted->paths()[2];
    {
        std::ofstream rewrite{swapped, std::ios::trunc};
        rewrite << "glvc_" << std::string(26, 'z') << "\n";
    }
    const auto removed = planted->paths()[0];
    planted->remove();
    REQUIRE(!std::filesystem::exists(removed));
    REQUIRE(std::filesystem::exists(changed));
    REQUIRE(std::filesystem::exists(swapped));
    std::filesystem::remove(swapped, ec);
    REQUIRE(journal_count(journal) == 0);
    std::filesystem::remove(changed, ec);

    // A fixed name another live launch planted is shared, not refused, and
    // stays until its owner removes it.
    const std::vector<std::string> fixed{(vault / "fixed_name").string()};
    auto owner = decoy_set::plant(fixed, exposed, journal);
    REQUIRE(owner.has_value());
    {
        auto sharer = decoy_set::plant(fixed, exposed, journal);
        REQUIRE(sharer.has_value());
        REQUIRE(sharer->paths() == owner->paths());
    }
    REQUIRE(std::filesystem::exists(vault / "fixed_name"));
    owner->remove();
    REQUIRE(!std::filesystem::exists(vault / "fixed_name"));

    // Moving the set keeps one owner.
    auto again = decoy_set::plant(templates, exposed, journal);
    REQUIRE(again.has_value());
    const auto kept = again->paths()[0];
    decoy_set moved = std::move(*again);
    again->remove(); // NOLINT(bugprone-use-after-move): a moved-from set owns nothing
    REQUIRE(std::filesystem::exists(kept));
    moved.remove();
    REQUIRE(!std::filesystem::exists(kept));
    return 0;
}

auto refuses(const std::filesystem::path& root) -> int {
    const auto home = root / "home2";
    const auto vault = home / "vault";
    const auto journal = root / "journal2";
    REQUIRE(private_directory(home) && private_directory(vault) && private_directory(journal));
    const auto plant = [&journal](
                           const std::vector<std::string>& templates,
                           const std::vector<std::string>& exposed
                       ) { return decoy_set::plant(templates, exposed, journal); };
    const auto ok = (vault / "ok_{nonce}").string();

    // Inside, or containing, a grant.
    REQUIRE(!plant({ok}, {vault.string()}).has_value());
    REQUIRE(!plant({ok}, {home.string()}).has_value());
    REQUIRE(!plant({(vault / "x").string()}, {(vault / "x" / "y").string()}).has_value());
    // Not a normal absolute file path below /.
    REQUIRE(!plant({"relative/x"}, {}).has_value());
    REQUIRE(!plant({(vault / ".." / "x").string()}, {}).has_value());
    REQUIRE(!plant({"/x"}, {}).has_value());
    // Missing, symlinked, or group-writable parent; glove never creates it.
    REQUIRE(!plant({(home / "absent" / "x").string()}, {}).has_value());
    REQUIRE(!std::filesystem::exists(home / "absent"));
    std::error_code ec;
    const auto alias = home / "alias";
    std::filesystem::create_directory_symlink(vault, alias, ec);
    REQUIRE(!ec);
    REQUIRE(!plant({(alias / "x").string()}, {}).has_value());
    const auto shared = home / "shared";
    std::filesystem::create_directory(shared, ec);
    std::filesystem::permissions(shared, static_cast<std::filesystem::perms>(0770), ec);
    REQUIRE(!ec);
    REQUIRE(!plant({(shared / "x").string()}, {}).has_value());
    // An existing file is never overwritten.
    const auto existing = vault / "existing";
    {
        std::ofstream real{existing};
        real << "real content\n";
    }
    REQUIRE(!plant({existing.string()}, {}).has_value());
    REQUIRE(read_file(existing) == "real content\n");
    // Listed twice, or too many.
    REQUIRE(!plant({(vault / "twice").string(), (vault / "twice").string()}, {}).has_value());
    std::vector<std::string> many;
    for (std::size_t i = 0; i <= glove::run::detail::max_decoys; ++i) {
        many.push_back((vault / ("many_" + std::to_string(i))).string());
    }
    REQUIRE(!plant(many, {}).has_value());

    // All or nothing: a refusal removes decoys already planted.
    REQUIRE(!plant({(vault / "first").string(), existing.string()}, {}).has_value());
    REQUIRE(!std::filesystem::exists(vault / "first"));
    REQUIRE(!std::filesystem::exists(vault / "twice"));
    REQUIRE(journal_count(journal) == 0);
    return 0;
}

auto sweeps_dead_launches(const std::filesystem::path& root) -> int {
    const auto dir = root / "home3";
    const auto journal = root / "journal3";
    REQUIRE(private_directory(dir) && private_directory(journal));
    // What a crashed launch leaves: an unlocked journal naming its decoys.
    const std::string canary = "glvc_aaaaaaaaaaaaaaaaaaaaaaaaaa";
    const auto ours = dir / "left_behind";
    const auto replaced = dir / "replaced";
    {
        std::ofstream decoy{ours};
        decoy << canary << "\n";
        std::ofstream other{replaced};
        other << "not a canary\n";
        std::ofstream list{journal / "launch-dead.list"};
        list << canary << "\t" << ours.string() << "\n"
             << canary << "\t" << replaced.string() << "\n"
             << "garbage line\n";
    }
    REQUIRE(glove::run::detail::sweep_stale_decoys(journal) == 1);
    REQUIRE(!std::filesystem::exists(ours));
    REQUIRE(std::filesystem::exists(replaced));
    REQUIRE(journal_count(journal) == 0);

    // An empty journal may belong to a launch that is just starting.
    { const std::ofstream fresh{journal / "launch-fresh.list"}; }
    REQUIRE(glove::run::detail::sweep_stale_decoys(journal) == 0);
    REQUIRE(journal_count(journal) == 1);
    return 0;
}

} // namespace

int main() {
    const temporary_tree tree;
    REQUIRE(!tree.path().empty());
    for (auto* step : {plants_and_removes, refuses, sweeps_dead_launches}) {
        if (const int failed = step(tree.path()); failed != 0) {
            return failed;
        }
    }
    std::printf("decoys ok\n");
    return 0;
}
