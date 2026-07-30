#!/usr/bin/env bash

set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
target=""
binary_dir=""
output_dir=""
source_revision="${GITHUB_SHA:-unknown}"

usage() {
    cat <<'EOF'
usage: scripts/package-release.sh --target <target> --binary-dir <dir> --output-dir <dir>

Packages prebuilt glove and gloved binaries with compatibility metadata,
service templates, documentation, checksums, and source identity.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            target="$2"
            shift 2
            ;;
        --binary-dir)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            binary_dir="$2"
            shift 2
            ;;
        --output-dir)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            output_dir="$2"
            shift 2
            ;;
        --source-revision)
            [[ $# -ge 2 ]] || { usage >&2; exit 2; }
            source_revision="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ -n "$target" && -n "$binary_dir" && -n "$output_dir" ]] || {
    usage >&2
    exit 2
}
[[ "$target" =~ ^[A-Za-z0-9._-]+$ ]] || {
    printf 'invalid release target: %s\n' "$target" >&2
    exit 2
}
[[ "$source_revision" == "unknown" || "$source_revision" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'invalid source revision\n' >&2
    exit 2
}

for executable in glove gloved; do
    [[ -f "$binary_dir/$executable" && -x "$binary_dir/$executable" ]] || {
        printf 'missing release executable: %s\n' "$binary_dir/$executable" >&2
        exit 1
    }
done

version="$("$binary_dir/glove" --version | awk 'NR == 1 && NF == 2 && $1 == "glove" { print $2 }')"
[[ -n "$version" ]] || {
    printf '%s\n' "release glove binary returned invalid version output" >&2
    exit 1
}
gloved_version="$("$binary_dir/gloved" --version | awk 'NR == 1 && NF == 2 && $1 == "gloved" { print $2 }')"
[[ "$gloved_version" == "$version" ]] || {
    printf 'glove/gloved version mismatch: %s vs %s\n' "$version" "$gloved_version" >&2
    exit 1
}

mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
staging="$(mktemp -d "${TMPDIR:-/tmp}/glove-release.XXXXXX")"
cleanup() {
    find "$staging" -mindepth 1 -delete
    rmdir "$staging"
}
trap cleanup EXIT

bundle="$staging/glove-$version-$target"
mkdir -p "$bundle/bin" "$bundle/share/glove/packaging" "$bundle/share/glove/scripts"
install -m 0755 "$binary_dir/glove" "$bundle/bin/glove"
install -m 0755 "$binary_dir/gloved" "$bundle/bin/gloved"
cp -R "$root/packaging/systemd" "$bundle/share/glove/packaging/systemd"
cp -R "$root/packaging/launchd" "$bundle/share/glove/packaging/launchd"
install -m 0644 "$root/docs/host-setup.md" "$bundle/share/glove/host-setup.md"
install -m 0755 \
    "$root/scripts/apple-container-session.sh" \
    "$bundle/share/glove/scripts/apple-container-session.sh"
sed \
    -e "s/@GLOVE_VERSION@/$version/g" \
    "$root/packaging/compatibility.json.in" \
    >"$bundle/share/glove/compatibility.json"
printf '%s\n' "$source_revision" >"$bundle/share/glove/source-revision"

if command -v sha256sum >/dev/null 2>&1; then
    (
        cd "$bundle"
        find bin share -type f -print | LC_ALL=C sort | xargs sha256sum
    ) >"$bundle/SHA256SUMS"
else
    (
        cd "$bundle"
        find bin share -type f -print | LC_ALL=C sort | xargs shasum -a 256
    ) >"$bundle/SHA256SUMS"
fi

archive="$output_dir/glove-$version-$target.tar.gz"
COPYFILE_DISABLE=1 tar -C "$staging" -czf "$archive" "$(basename "$bundle")"
if tar -tzf "$archive" | grep -Eq '(^|/)(\._|__MACOSX(/|$))'; then
    printf '%s\n' "release archive contains forbidden macOS metadata sidecars" >&2
    exit 1
fi

# Validate the archive as a consumer sees it, not only the staging tree.
verification_root="$staging/verification"
mkdir -p "$verification_root"
tar -C "$verification_root" -xzf "$archive"
verified_bundle="$verification_root/$(basename "$bundle")"
(
    cd "$verified_bundle"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum --check SHA256SUMS
    else
        shasum -a 256 --check SHA256SUMS
    fi
)
[[ "$("$verified_bundle/bin/glove" --version)" == "glove $version" ]]
[[ "$("$verified_bundle/bin/gloved" --version)" == "gloved $version" ]]
python3 - "$verified_bundle/share/glove/compatibility.json" "$target" <<'PY'
import json
import sys

manifest_path, target = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)

platforms = manifest["platforms"]
linux = platforms["linux"]
macos = platforms["macos"]
if linux.get("managed_session_backend") != "linux_production":
    raise SystemExit("Linux release manifest omits the managed-session backend")
if linux.get("managed_session_protocol_available") is not True:
    raise SystemExit("Linux release manifest disables the managed-session protocol")
if macos.get("shipping_backend") != "apple_container":
    raise SystemExit("macOS release manifest omits the Apple Container shipping backend")
if macos.get("managed_session_backend") != "apple_container":
    raise SystemExit("macOS release manifest omits its managed-session backend")
if macos.get("managed_session_protocol_available") is not True:
    raise SystemExit("macOS release manifest disables managed sessions")
if macos.get("agent_runtime_adapter_schema_version") != 1:
    raise SystemExit("macOS release manifest omits the managed adapter schema")
if macos.get("runtime_identity_source") != "paired_sage_release":
    raise SystemExit("macOS release manifest does not bind runtime identity to the pair")
if target.endswith("-apple-darwin") and macos["shipping_backend"] != "apple_container":
    raise SystemExit("Apple release does not declare its shipping backend")
PY

if command -v sha256sum >/dev/null 2>&1; then
    (
        cd "$(dirname "$archive")"
        sha256sum "$(basename "$archive")"
    ) >"$archive.sha256"
else
    (
        cd "$(dirname "$archive")"
        shasum -a 256 "$(basename "$archive")"
    ) >"$archive.sha256"
fi
printf '%s\n' "$archive"
