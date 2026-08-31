#include "glove/container/digest.hpp"
#include "glove/supervisor/codex_runtime_adapter.hpp"
#include "glove/supervisor/library_bundle.hpp"
#include "glove/supervisor/native_skill_runtime_adapter.hpp"
#include "glove/supervisor/sage_bundle_projection.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace {

#define REQUIRE(cond)                                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "REQUIRE failed: %s @ %s:%d\n", #cond, __FILE__, __LINE__);       \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

class temporary_directory {
public:
    temporary_directory() {
        std::string pattern = "/tmp/glove-library-bundle-test-XXXXXX";
        if (char* created = ::mkdtemp(pattern.data()); created != nullptr) {
            root_ = created;
        }
    }

    temporary_directory(const temporary_directory&) = delete;
    auto operator=(const temporary_directory&) -> temporary_directory& = delete;

    ~temporary_directory() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    [[nodiscard]] auto root() const -> const std::filesystem::path& { return root_; }

private:
    std::filesystem::path root_;
};

auto digest_for(std::string_view value) -> std::string {
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    return glove::container::sha256_hex(std::span{bytes, value.size()}).value_or("");
}

auto write_bundle(const std::filesystem::path& root, std::string_view contents, mode_t mode = 0600)
    -> std::filesystem::path {
    const auto path = root / (digest_for(contents) + ".json");
    {
        std::ofstream output{path, std::ios::binary | std::ios::trunc};
        output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }
    static_cast<void>(::chmod(path.c_str(), mode));
    return path;
}

auto read_descriptor(int descriptor, std::size_t size) -> std::string {
    std::string contents(size, '\0');
    const auto count = ::pread(descriptor, contents.data(), contents.size(), 0);
    if (count != static_cast<ssize_t>(contents.size())) {
        return {};
    }
    return contents;
}

struct bundle_test_entry {
    std::string key;
    std::string kind;
    std::string content;
    std::optional<std::string> content_digest;
};

auto test_entry(
    std::string key,
    std::string kind,
    std::string content,
    std::optional<std::string> content_digest = std::nullopt
) -> bundle_test_entry {
    return {
        .key = std::move(key),
        .kind = std::move(kind),
        .content = std::move(content),
        .content_digest = std::move(content_digest),
    };
}

auto json_string(std::string_view value) -> std::string {
    std::string encoded{"\""};
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        switch (byte) {
        case '\0':
            encoded += "\\u0000";
            break;
        case '\n':
            encoded += "\\n";
            break;
        case '\\':
            encoded += "\\\\";
            break;
        case '"':
            encoded += "\\\"";
            break;
        default:
            encoded.push_back(static_cast<char>(byte));
            break;
        }
    }
    encoded.push_back('"');
    return encoded;
}

auto bundle_json(const std::vector<bundle_test_entry>& entries) -> std::string {
    std::string encoded =
        R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[)";
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        if (index != 0U) {
            encoded.push_back(',');
        }
        encoded += "{\"key\":" + json_string(entry.key) + ",\"kind\":" + json_string(entry.kind) +
                   ",\"content_digest\":" +
                   json_string(entry.content_digest.value_or(digest_for(entry.content))) +
                   ",\"content\":" + json_string(entry.content) + "}";
    }
    encoded += "]}";
    return encoded;
}

auto run() -> int {
    temporary_directory temporary;
    REQUIRE(!temporary.root().empty());
    const auto root = temporary.root() / "bundles";
    REQUIRE(std::filesystem::create_directory(root));
    REQUIRE(::chmod(root.c_str(), 0700) == 0);

    constexpr std::string_view canonical =
        R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[]})";
    const auto digest = digest_for(canonical);
    REQUIRE(digest.size() == 64U);
    const auto bundle_path = write_bundle(root, canonical);

    auto store = glove::supervisor::library_bundle_store::open(root);
    REQUIRE(store.has_value());
    auto resolved = store->resolve(digest);
    REQUIRE(resolved.has_value());
    REQUIRE(resolved->content_digest() == digest);
    REQUIRE(resolved->size_bytes() == canonical.size());
    REQUIRE(read_descriptor(resolved->descriptor_fd(), canonical.size()) == canonical);
    REQUIRE(resolved->verify_identity().has_value());

    std::vector<glove::supervisor::resolved_library_projection_target> targets;
    targets.push_back({
        .projection =
            {
                .projection_id = "sage-core",
                .content_digest = digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    auto projections = store->resolve_projections(targets);
    REQUIRE(projections.has_value());
    REQUIRE(projections->size() == 1U);
    REQUIRE(projections->front().projection_id == "sage-core");
    REQUIRE(projections->front().destination_alias == "libraries");
    REQUIRE(projections->front().target_path == "/opt/sage/library-bundles/" + digest + ".json");
    REQUIRE(projections->front().bundle.content_digest() == digest);
    REQUIRE(projections->front().bundle.verify_identity().has_value());

    auto sage_projection_digest = glove::supervisor::sage_bundle_projection_digest(*projections);
    REQUIRE(sage_projection_digest.has_value());
    REQUIRE(sage_projection_digest->size() == 64U);
    const auto sage_projection_root = temporary.root() / "sage-bundles";
    REQUIRE(std::filesystem::create_directory(sage_projection_root));
    REQUIRE(::chmod(sage_projection_root.c_str(), 0700) == 0);
    const int sage_projection_fd =
        ::open(sage_projection_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(sage_projection_fd >= 0);
    REQUIRE(
        glove::supervisor::materialize_sage_bundle_projection(sage_projection_fd, *projections)
            .has_value()
    );
    ::close(sage_projection_fd);
    const auto projected_bundle = sage_projection_root / (digest + ".json");
    std::ifstream projected_input{projected_bundle, std::ios::binary};
    const std::string projected_contents{
        std::istreambuf_iterator<char>{projected_input}, std::istreambuf_iterator<char>{}
    };
    REQUIRE(projected_contents == canonical);
    struct stat projected_status{};
    REQUIRE(::lstat(projected_bundle.c_str(), &projected_status) == 0);
    REQUIRE((static_cast<unsigned int>(projected_status.st_mode) & 0777U) == 0444U);
    REQUIRE(::chmod(sage_projection_root.c_str(), 0700) == 0);

    std::vector<glove::supervisor::resolved_library_projection_target> oversized_targets;
    for (std::size_t index = 0; index < 5U; ++index) {
        std::string contents(
            static_cast<std::size_t>(glove::supervisor::max_library_bundle_bytes) - 1U,
            static_cast<char>('a' + index)
        );
        const auto content_digest = digest_for(contents);
        write_bundle(root, contents);
        oversized_targets.push_back({
            .projection =
                {
                    .projection_id = "large-" + std::to_string(index),
                    .content_digest = content_digest,
                    .destination_alias = "sage-bundles",
                },
            .target_path = "/opt/sage/library-bundles",
        });
    }
    auto oversized_projections = store->resolve_projections(oversized_targets);
    REQUIRE(oversized_projections.has_value());
    const auto oversized_projection_root = temporary.root() / "oversized-sage-bundles";
    REQUIRE(std::filesystem::create_directory(oversized_projection_root));
    REQUIRE(::chmod(oversized_projection_root.c_str(), 0700) == 0);
    const int oversized_projection_fd =
        ::open(oversized_projection_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(oversized_projection_fd >= 0);
    REQUIRE(!glove::supervisor::materialize_sage_bundle_projection(
                 oversized_projection_fd, *oversized_projections
    )
                 .has_value());
    ::close(oversized_projection_fd);
    REQUIRE(std::filesystem::is_empty(oversized_projection_root));

    constexpr std::string_view codex_canonical =
        R"({"schema_version":1,"source_library_ref":"bafy-codex","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[{"key":"sage-core","kind":"skill","content_digest":"a8095aa5472d84253e87441d7438235d2b13c13e09de63cbb88609931b8b8947","content":"# Sage core\n"}]})";
    const auto codex_digest = digest_for(codex_canonical);
    write_bundle(root, codex_canonical);
    std::vector<glove::supervisor::resolved_library_projection_target> codex_targets;
    codex_targets.push_back({
        .projection =
            {
                .projection_id = "sage-codex",
                .content_digest = codex_digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    auto codex_projections = store->resolve_projections(codex_targets);
    REQUIRE(codex_projections.has_value());
    auto codex = glove::supervisor::resolve_codex_runtime_projection(*codex_projections);
    REQUIRE(codex.has_value());
    REQUIRE(codex->skills.size() == 1U);
    REQUIRE(codex->skills.front().projection_id == "sage-codex");
    REQUIRE(codex->skills.front().key == "sage-core");
    REQUIRE(codex->skills.front().content == "# Sage core\n");
    auto codex_projection_digest = glove::supervisor::codex_runtime_projection_digest(*codex);
    REQUIRE(codex_projection_digest.has_value());
    REQUIRE(codex_projection_digest->size() == 64U);
    auto reordered_codex = *codex;
    std::ranges::reverse(reordered_codex.skills);
    REQUIRE(
        glove::supervisor::codex_runtime_projection_digest(reordered_codex) ==
        codex_projection_digest
    );
    reordered_codex.skills.front().content = "# changed\n";
    REQUIRE(!glove::supervisor::codex_runtime_projection_digest(reordered_codex).has_value());

    const auto rejects_bundle_json = [&](std::string projection_id, const std::string& contents) {
        write_bundle(root, contents);
        auto candidate = store->resolve_projections({{
            .projection =
                {
                    .projection_id = std::move(projection_id),
                    .content_digest = digest_for(contents),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        }});
        return candidate.has_value() &&
               !glove::supervisor::resolve_codex_runtime_projection(*candidate).has_value();
    };
    const auto insert_json_member =
        [](std::string document, std::string_view before, std::string_view member) {
            const auto position = document.find(before);
            if (position == std::string::npos) {
                return std::string{};
            }
            document.insert(position, member);
            return document;
        };
    const auto duplicate_member_base = bundle_json({
        test_entry("trusted-key", "skill", "trusted content"),
    });

    REQUIRE(rejects_bundle_json(
        "duplicate-top-plain",
        insert_json_member(duplicate_member_base, R"("entries":)", R"("entries":[],)")
    ));
    REQUIRE(rejects_bundle_json(
        "duplicate-top-escaped",
        insert_json_member(duplicate_member_base, R"("entries":)", R"("entr\u0069es":[],)")
    ));

    struct duplicate_entry_member_case {
        std::string_view name;
        std::string_view marker;
        std::string_view plain_member;
        std::string_view escaped_member;
    };

    const std::array duplicate_entry_member_cases{
        duplicate_entry_member_case{
            "key",
            R"("key":)",
            R"("key":"other-key",)",
            R"("k\u0065y":"other-key",)",
        },
        duplicate_entry_member_case{
            "kind",
            R"("kind":)",
            R"("kind":"prompt",)",
            R"("ki\u006ed":"prompt",)",
        },
        duplicate_entry_member_case{
            "content",
            R"("content":)",
            R"("content":"altered content",)",
            R"("cont\u0065nt":"altered content",)",
        },
        duplicate_entry_member_case{
            "content-digest",
            R"("content_digest":)",
            R"("content_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",)",
            R"("content_dig\u0065st":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",)",
        },
    };
    for (const auto& duplicate : duplicate_entry_member_cases) {
        REQUIRE(rejects_bundle_json(
            "duplicate-entry-plain-" + std::string{duplicate.name},
            insert_json_member(duplicate_member_base, duplicate.marker, duplicate.plain_member)
        ));
        REQUIRE(rejects_bundle_json(
            "duplicate-entry-escaped-" + std::string{duplicate.name},
            insert_json_member(duplicate_member_base, duplicate.marker, duplicate.escaped_member)
        ));
    }

    std::string excessive_nesting =
        R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":)";
    excessive_nesting.append(65U, '[');
    excessive_nesting += "null";
    excessive_nesting.append(65U, ']');
    excessive_nesting.push_back('}');
    REQUIRE(rejects_bundle_json("excessive-json-nesting", excessive_nesting));

    // A skill directory is a single filesystem component. Reject an otherwise
    // syntactically valid projection before materialization rather than letting
    // a host filesystem limit decide the launch result.
    auto oversized_directory = *codex;
    oversized_directory.skills.front().projection_id = std::string(128U, 'p');
    oversized_directory.skills.front().key = std::string(128U, 'k');
    REQUIRE(!glove::supervisor::codex_runtime_projection_digest(oversized_directory).has_value());
    const auto oversized_home = temporary.root() / "oversized-codex-home";
    REQUIRE(std::filesystem::create_directory(oversized_home));
    const int oversized_home_fd =
        ::open(oversized_home.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(oversized_home_fd >= 0);
    REQUIRE(!glove::supervisor::materialize_codex_runtime_projection(
                 oversized_home_fd, oversized_directory
    )
                 .has_value());
    ::close(oversized_home_fd);
    REQUIRE(std::filesystem::is_empty(oversized_home));

    const auto mixed_codex_canonical = bundle_json({
        test_entry("sage-core", "skill", "# Sage core\n"),
        test_entry("selected-prompt", "prompt", "prompt body\n"),
        test_entry("review-cycle", "behavior", "behavior graph\n"),
        test_entry("issue-template", "template", "template body\n"),
        test_entry("release-workflow", "workflow", "workflow body\n"),
    });
    const auto mixed_codex_digest = digest_for(mixed_codex_canonical);
    write_bundle(root, mixed_codex_canonical);
    std::vector<glove::supervisor::resolved_library_projection_target> mixed_codex_targets;
    mixed_codex_targets.push_back({
        .projection =
            {
                .projection_id = "sage-mixed",
                .content_digest = mixed_codex_digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    auto mixed_codex_projections = store->resolve_projections(mixed_codex_targets);
    REQUIRE(mixed_codex_projections.has_value());
    auto mixed_codex =
        glove::supervisor::resolve_codex_runtime_projection(*mixed_codex_projections);
    REQUIRE(mixed_codex.has_value());
    REQUIRE(mixed_codex->skills.size() == 1U);
    REQUIRE(mixed_codex->skills.front().key == "sage-core");
    REQUIRE(mixed_codex->unmaterialized_entries.size() == 4U);
    REQUIRE(mixed_codex->unmaterialized_entries[0].key == "issue-template");
    REQUIRE(mixed_codex->unmaterialized_entries[0].kind == "template");
    REQUIRE(mixed_codex->unmaterialized_entries[1].kind == "workflow");
    REQUIRE(mixed_codex->unmaterialized_entries[2].kind == "behavior");
    REQUIRE(mixed_codex->unmaterialized_entries[3].kind == "prompt");
    auto mixed_projection_digest = glove::supervisor::codex_runtime_projection_digest(*mixed_codex);
    REQUIRE(mixed_projection_digest.has_value());
    REQUIRE(*mixed_projection_digest != *codex_projection_digest);
    auto changed_metadata = *mixed_codex;
    changed_metadata.unmaterialized_entries.front().kind = "workflow";
    auto changed_metadata_digest =
        glove::supervisor::codex_runtime_projection_digest(changed_metadata);
    REQUIRE(changed_metadata_digest.has_value());
    REQUIRE(*changed_metadata_digest != *mixed_projection_digest);
    auto duplicate_across_kinds = *mixed_codex;
    duplicate_across_kinds.unmaterialized_entries.front().key = "sage-core";
    REQUIRE(!glove::supervisor::codex_runtime_projection_digest(duplicate_across_kinds));

    const auto all_non_skill_canonical = bundle_json({
        test_entry("behavior", "behavior", "behavior"),
        test_entry("prompt", "prompt", "prompt"),
        test_entry("template", "template", "template"),
        test_entry("workflow", "workflow", "workflow"),
    });
    write_bundle(root, all_non_skill_canonical);
    auto all_non_skill_projections = store->resolve_projections({{
        .projection =
            {
                .projection_id = "all-non-skill",
                .content_digest = digest_for(all_non_skill_canonical),
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    }});
    REQUIRE(all_non_skill_projections.has_value());
    auto all_non_skill =
        glove::supervisor::resolve_codex_runtime_projection(*all_non_skill_projections);
    REQUIRE(all_non_skill.has_value());
    REQUIRE(all_non_skill->skills.empty());
    REQUIRE(all_non_skill->unmaterialized_entries.size() == 4U);
    REQUIRE(glove::supervisor::codex_runtime_projection_digest(*all_non_skill).has_value());

    constexpr std::string_view unknown_codex_canonical =
        R"({"schema_version":1,"source_library_ref":"bafy-codex","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[{"key":"selected-prompt","kind":"skill_v2","content_digest":"3514cf816e5407a39cb7a1c1e1243f176dda121e06398a8934edb1dc426b0b34","content":"ignored"}]})";
    const auto unknown_codex_digest = digest_for(unknown_codex_canonical);
    write_bundle(root, unknown_codex_canonical);
    std::vector<glove::supervisor::resolved_library_projection_target> unknown_codex_targets;
    unknown_codex_targets.push_back({
        .projection =
            {
                .projection_id = "sage-unknown",
                .content_digest = unknown_codex_digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    auto unknown_codex_projections = store->resolve_projections(unknown_codex_targets);
    REQUIRE(unknown_codex_projections.has_value());
    REQUIRE(!glove::supervisor::resolve_codex_runtime_projection(*unknown_codex_projections));

    const auto rejects_entry = [&](std::string projection_id, bundle_test_entry entry) {
        const auto contents = bundle_json({std::move(entry)});
        write_bundle(root, contents);
        auto candidate = store->resolve_projections({{
            .projection =
                {
                    .projection_id = std::move(projection_id),
                    .content_digest = digest_for(contents),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        }});
        return candidate.has_value() &&
               !glove::supervisor::resolve_codex_runtime_projection(*candidate).has_value();
    };
    REQUIRE(rejects_entry("empty-entry", test_entry("empty", "prompt", "")));
    REQUIRE(rejects_entry("nul-entry", test_entry("nul", "workflow", std::string{"x\0y", 3U})));
    REQUIRE(rejects_entry(
        "digest-mismatch", test_entry("mismatch", "template", "content", std::string(64U, 'f'))
    ));
    REQUIRE(rejects_entry(
        "oversized-entry", test_entry("large", "behavior", std::string(1024U * 1024U + 1U, 'x'))
    ));
    constexpr std::string_view malformed_known_entry =
        R"({"schema_version":1,"source_library_ref":"bafy-test","source_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entries":[{"key":"missing-content","kind":"prompt","content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]})";
    write_bundle(root, malformed_known_entry);
    auto malformed_known_projection = store->resolve_projections({{
        .projection =
            {
                .projection_id = "malformed-known",
                .content_digest = digest_for(malformed_known_entry),
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    }});
    REQUIRE(malformed_known_projection.has_value());
    REQUIRE(!glove::supervisor::resolve_codex_runtime_projection(*malformed_known_projection));

    std::vector<bundle_test_entry> maximum_entries;
    maximum_entries.reserve(4'096U);
    for (std::size_t index = 0; index < 4'096U; ++index) {
        maximum_entries.push_back(test_entry("key-" + std::to_string(index), "prompt", "x"));
    }
    const auto maximum_entries_bundle = bundle_json(maximum_entries);
    const auto one_more_entry_bundle = bundle_json({
        test_entry("one-more", "workflow", "x"),
    });
    write_bundle(root, maximum_entries_bundle);
    write_bundle(root, one_more_entry_bundle);
    auto too_many_entries = store->resolve_projections({
        {
            .projection =
                {
                    .projection_id = "entry-bound-a",
                    .content_digest = digest_for(maximum_entries_bundle),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        },
        {
            .projection =
                {
                    .projection_id = "entry-bound-b",
                    .content_digest = digest_for(one_more_entry_bundle),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        },
    });
    REQUIRE(too_many_entries.has_value());
    REQUIRE(!glove::supervisor::resolve_codex_runtime_projection(*too_many_entries));

    std::vector<glove::supervisor::resolved_library_projection_target> byte_bound_targets;
    for (std::size_t index = 0; index < 17U; ++index) {
        const auto contents = bundle_json({test_entry(
            "large-" + std::to_string(index),
            "prompt",
            std::string(1024U * 1024U, static_cast<char>('a' + index))
        )});
        const auto content_digest = digest_for(contents);
        write_bundle(root, contents);
        byte_bound_targets.push_back({
            .projection =
                {
                    .projection_id = "byte-bound-" + std::to_string(index),
                    .content_digest = content_digest,
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        });
    }
    auto too_many_bytes = store->resolve_projections(byte_bound_targets);
    REQUIRE(too_many_bytes.has_value());
    REQUIRE(!glove::supervisor::resolve_codex_runtime_projection(*too_many_bytes));

    const auto duplicate_first = bundle_json({
        test_entry("same-key", "skill", "skill"),
    });
    const auto duplicate_second = bundle_json({
        test_entry("same-key", "prompt", "prompt"),
    });
    write_bundle(root, duplicate_first);
    write_bundle(root, duplicate_second);
    auto duplicate_across_bundles = store->resolve_projections({
        {
            .projection =
                {
                    .projection_id = "duplicate-projection",
                    .content_digest = digest_for(duplicate_first),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        },
        {
            .projection =
                {
                    .projection_id = "duplicate-projection",
                    .content_digest = digest_for(duplicate_second),
                    .destination_alias = "libraries",
                },
            .target_path = "/opt/sage/library-bundles",
        },
    });
    REQUIRE(duplicate_across_bundles.has_value());
    REQUIRE(!glove::supervisor::resolve_codex_runtime_projection(*duplicate_across_bundles));
    const auto duplicate_across_kinds_bundle = bundle_json({
        test_entry("same-key", "skill", "skill"),
        test_entry("same-key", "workflow", "workflow"),
    });
    write_bundle(root, duplicate_across_kinds_bundle);
    auto duplicate_across_kinds_projection = store->resolve_projections({{
        .projection =
            {
                .projection_id = "duplicate-kinds",
                .content_digest = digest_for(duplicate_across_kinds_bundle),
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    }});
    REQUIRE(duplicate_across_kinds_projection.has_value());
    REQUIRE(
        !glove::supervisor::resolve_codex_runtime_projection(*duplicate_across_kinds_projection)
    );

    auto order_targets = std::vector<glove::supervisor::resolved_library_projection_target>{
        codex_targets.front(), mixed_codex_targets.front()
    };
    auto forward_order = store->resolve_projections(order_targets);
    std::ranges::reverse(order_targets);
    auto reverse_order = store->resolve_projections(order_targets);
    REQUIRE(forward_order.has_value());
    REQUIRE(reverse_order.has_value());
    auto forward_projection = glove::supervisor::resolve_codex_runtime_projection(*forward_order);
    auto reverse_projection = glove::supervisor::resolve_codex_runtime_projection(*reverse_order);
    REQUIRE(forward_projection.has_value());
    REQUIRE(reverse_projection.has_value());
    REQUIRE(
        glove::supervisor::codex_runtime_projection_digest(*forward_projection) ==
        glove::supervisor::codex_runtime_projection_digest(*reverse_projection)
    );

    const auto raw_mixed_root = temporary.root() / "raw-mixed-bundles";
    REQUIRE(std::filesystem::create_directory(raw_mixed_root));
    REQUIRE(::chmod(raw_mixed_root.c_str(), 0700) == 0);
    const int raw_mixed_fd =
        ::open(raw_mixed_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(raw_mixed_fd >= 0);
    REQUIRE(
        glove::supervisor::materialize_sage_bundle_projection(
            raw_mixed_fd, *mixed_codex_projections
        )
            .has_value()
    );
    ::close(raw_mixed_fd);
    std::ifstream raw_mixed_input{
        raw_mixed_root / (mixed_codex_digest + ".json"), std::ios::binary
    };
    const std::string raw_mixed_contents{
        std::istreambuf_iterator<char>{raw_mixed_input}, std::istreambuf_iterator<char>{}
    };
    REQUIRE(raw_mixed_contents == mixed_codex_canonical);

    const auto admission_adapter =
        glove::supervisor::native_skill_runtime_adapter_for("claude-code");
    REQUIRE(admission_adapter.has_value());
    auto native_mixed = glove::supervisor::resolve_native_skill_runtime_projection(
        *admission_adapter, *mixed_codex_projections
    );
    REQUIRE(native_mixed.has_value());
    REQUIRE(native_mixed->unmaterialized_entries.size() == 4U);
    REQUIRE(glove::supervisor::native_skill_runtime_projection_requires_raw_bundle(*native_mixed));
    auto native_mixed_digest = glove::supervisor::native_skill_runtime_projection_digest(
        *admission_adapter, *native_mixed
    );
    REQUIRE(native_mixed_digest.has_value());
    auto native_metadata_removed = *native_mixed;
    native_metadata_removed.unmaterialized_entries.clear();
    auto native_metadata_removed_digest = glove::supervisor::native_skill_runtime_projection_digest(
        *admission_adapter, native_metadata_removed
    );
    REQUIRE(native_metadata_removed_digest.has_value());
    REQUIRE(*native_metadata_removed_digest != *native_mixed_digest);
    auto native_skill_only = glove::supervisor::resolve_native_skill_runtime_projection(
        *admission_adapter, *codex_projections
    );
    REQUIRE(native_skill_only.has_value());
    REQUIRE(
        !glove::supervisor::native_skill_runtime_projection_requires_raw_bundle(*native_skill_only)
    );

    // Every built-in harness consumes the same verified Agent Skills bundle,
    // but receives it in an adapter-owned private-home layout. This proves the
    // generic adapter is not a Codex-only projection with renamed metadata.
    const auto native_homes = temporary.root() / "native-homes";
    REQUIRE(std::filesystem::create_directory(native_homes));
    REQUIRE(::chmod(native_homes.c_str(), 0700) == 0);
    for (const std::string_view runtime_id : {
             "codex",
             "claude-code",
             "pi",
             "copilot",
             "opencode",
         }) {
        const auto adapter = glove::supervisor::native_skill_runtime_adapter_for(runtime_id);
        REQUIRE(adapter.has_value());
        if (runtime_id == "codex") {
            REQUIRE(
                adapter->managed_arguments ==
                std::vector<std::string>{"--dangerously-bypass-approvals-and-sandbox"}
            );
            REQUIRE(adapter->managed_configuration.has_value());
            REQUIRE(adapter->managed_configuration->filename == "config.toml");
        } else {
            REQUIRE(adapter->managed_arguments.empty());
            if (runtime_id != "pi") {
                REQUIRE(!adapter->managed_configuration);
                REQUIRE(!adapter->adoption_manifest);
            } else {
                REQUIRE(adapter->adoption_manifest.has_value());
                REQUIRE(adapter->adoption_manifest->require_snapshot);
                const std::vector<std::string> expected_source_artifacts{
                    "runtime-executable", "runtime-dependency-closure"
                };
                REQUIRE(
                    adapter->adoption_manifest->source_artifact_ids == expected_source_artifacts
                );
                REQUIRE(
                    std::ranges::find(
                        adapter->adoption_manifest->excluded_host_state_ids, "host-auth"
                    ) != adapter->adoption_manifest->excluded_host_state_ids.end()
                );
                auto manifest_digest =
                    glove::supervisor::native_harness_adoption_manifest_digest(*adapter);
                REQUIRE(manifest_digest.has_value());
                REQUIRE(manifest_digest->size() == 64U);
            }
        }
        auto native = glove::supervisor::resolve_native_skill_runtime_projection(
            *adapter, *codex_projections
        );
        REQUIRE(native.has_value());
        auto native_digest =
            glove::supervisor::native_skill_runtime_projection_digest(*adapter, *native);
        REQUIRE(native_digest.has_value());
        REQUIRE(native_digest->size() == 64U);

        const auto home = native_homes / std::string{runtime_id};
        REQUIRE(std::filesystem::create_directory(home));
        const int home_fd = ::open(home.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        REQUIRE(home_fd >= 0);
        const auto materialized = glove::supervisor::materialize_native_skill_runtime_projection(
            home_fd, *adapter, *native
        );
        ::close(home_fd);
        REQUIRE(materialized.has_value());
        auto skill_path = home;
        for (const auto& component : adapter->skill_root_components) {
            skill_path /= component;
        }
        skill_path /= "sage-codex-sage-core";
        skill_path /= "SKILL.md";
        REQUIRE(std::filesystem::is_regular_file(skill_path));
        std::ifstream materialized_skill{skill_path, std::ios::binary};
        REQUIRE(static_cast<bool>(materialized_skill));
        std::string materialized_contents{
            std::istreambuf_iterator<char>{materialized_skill}, std::istreambuf_iterator<char>{}
        };
        REQUIRE(materialized_contents == "# Sage core\n");
        if (runtime_id == "codex") {
            std::ifstream managed_config{home / ".codex/config.toml", std::ios::binary};
            REQUIRE(static_cast<bool>(managed_config));
            const std::string config_contents{
                std::istreambuf_iterator<char>{managed_config},
                std::istreambuf_iterator<char>{},
            };
            REQUIRE(config_contents.find("[projects.\"/home/agent\"]") != std::string::npos);
            REQUIRE(config_contents.find("trust_level = \"trusted\"") != std::string::npos);
        }
        if (runtime_id == "pi") {
            std::ifstream managed_config{home / ".pi/agent/settings.json", std::ios::binary};
            REQUIRE(static_cast<bool>(managed_config));
            const std::string config_contents{
                std::istreambuf_iterator<char>{managed_config},
                std::istreambuf_iterator<char>{},
            };
            REQUIRE(config_contents == "{\"packages\":[],\"enableSkillCommands\":true}\n");
        }
    }
    REQUIRE(!glove::supervisor::native_skill_runtime_adapter_for("untrusted-runtime"));

    auto duplicate_targets = targets;
    duplicate_targets.push_back({
        .projection =
            {
                .projection_id = "sage-duplicate",
                .content_digest = digest,
                .destination_alias = "libraries",
            },
        .target_path = "/opt/sage/library-bundles",
    });
    REQUIRE(!store->resolve_projections(duplicate_targets).has_value());

    auto unavailable_targets = targets;
    unavailable_targets.front().projection.content_digest = std::string(64U, 'f');
    REQUIRE(!store->resolve_projections(unavailable_targets).has_value());

    REQUIRE(!store->resolve(std::string(64U, 'A')).has_value());
    REQUIRE(!store->resolve(std::string(63U, 'a')).has_value());
    REQUIRE(!glove::supervisor::library_bundle_store::open("relative/bundles").has_value());

    const auto unsafe_root = temporary.root() / "unsafe";
    REQUIRE(std::filesystem::create_directory(unsafe_root));
    REQUIRE(::chmod(unsafe_root.c_str(), 0755) == 0);
    REQUIRE(!glove::supervisor::library_bundle_store::open(unsafe_root).has_value());

    const auto symlink_root = temporary.root() / "bundle-link";
    REQUIRE(::symlink(root.c_str(), symlink_root.c_str()) == 0);
    REQUIRE(!glove::supervisor::library_bundle_store::open(symlink_root).has_value());

    constexpr std::string_view loose = R"({"schema_version":1,"entries":["loose"]})";
    const auto loose_path = write_bundle(root, loose, 0644);
    REQUIRE(!store->resolve(digest_for(loose)).has_value());

    constexpr std::string_view linked = R"({"schema_version":1,"entries":["linked"]})";
    const auto linked_path = write_bundle(root, linked);
    const auto second_link = temporary.root() / "second-link.json";
    REQUIRE(::link(linked_path.c_str(), second_link.c_str()) == 0);
    REQUIRE(!store->resolve(digest_for(linked)).has_value());

    constexpr std::string_view redirected = R"({"schema_version":1,"entries":["redirected"]})";
    const auto redirected_digest = digest_for(redirected);
    const auto outside = write_bundle(temporary.root(), redirected);
    const auto redirected_path = root / (redirected_digest + ".json");
    REQUIRE(::symlink(outside.c_str(), redirected_path.c_str()) == 0);
    REQUIRE(!store->resolve(redirected_digest).has_value());

    constexpr std::string_view expected = R"({"schema_version":1,"entries":["expected"]})";
    constexpr std::string_view corrupted = R"({"schema_version":1,"entries":["corrupt!"]})";
    REQUIRE(expected.size() == corrupted.size());
    const auto expected_digest = digest_for(expected);
    const auto corrupted_path = root / (expected_digest + ".json");
    {
        std::ofstream output{corrupted_path, std::ios::binary | std::ios::trunc};
        output.write(corrupted.data(), static_cast<std::streamsize>(corrupted.size()));
    }
    REQUIRE(::chmod(corrupted_path.c_str(), 0600) == 0);
    REQUIRE(!store->resolve(expected_digest).has_value());

    constexpr std::string_view mutable_bundle = R"({"schema_version":1,"entries":["mutable-a"]})";
    constexpr std::string_view changed_bundle = R"({"schema_version":1,"entries":["mutable-b"]})";
    REQUIRE(mutable_bundle.size() == changed_bundle.size());
    const auto mutable_path = write_bundle(root, mutable_bundle);
    auto mutable_resolved = store->resolve(digest_for(mutable_bundle));
    REQUIRE(mutable_resolved.has_value());
    {
        std::ofstream output{mutable_path, std::ios::binary | std::ios::trunc};
        output.write(changed_bundle.data(), static_cast<std::streamsize>(changed_bundle.size()));
    }
    REQUIRE(::chmod(mutable_path.c_str(), 0600) == 0);
    REQUIRE(!mutable_resolved->verify_identity().has_value());

    REQUIRE(::chmod(bundle_path.c_str(), 0400) == 0);
    REQUIRE(!resolved->verify_identity().has_value());

    REQUIRE(::chmod(root.c_str(), 0755) == 0);
    REQUIRE(!store->resolve(digest).has_value());
    REQUIRE(::chmod(root.c_str(), 0700) == 0);

    const auto original_root = temporary.root() / "original-bundles";
    std::filesystem::rename(root, original_root);
    REQUIRE(std::filesystem::is_directory(original_root));
    REQUIRE(std::filesystem::create_directory(root));
    REQUIRE(::chmod(root.c_str(), 0700) == 0);
    REQUIRE(!store->resolve(digest).has_value());

    static_cast<void>(loose_path);
    return 0;
}

} // namespace

auto main() -> int {
    return run();
}
