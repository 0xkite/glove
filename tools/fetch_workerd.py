#!/usr/bin/env python3
"""Fetch and install the single pinned workerd Linux artifact.

The command intentionally has no URL, package-manager, lifecycle-hook, or generic
archive-extraction option.  Its only network input is the URL in the adjacent
schema-versioned manifest, which is checked against the compiled-in identity.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import hashlib
import hmac
import json
import os
import stat
import tarfile
import tempfile
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import IO, BinaryIO, NoReturn

MANIFEST_PATH = Path(__file__).with_name("workerd-linux-64.json")
_DOWNLOAD_CHUNK_BYTES = 1024 * 1024
_DOWNLOAD_TIMEOUT_SECONDS = 60
_MANIFEST_BYTES_MAX = 32 * 1024

_PINNED_PACKAGE = "@cloudflare/workerd-linux-64"
_PINNED_VERSION = "1.20260807.2"
_PINNED_URL = (
    "https://registry.npmjs.org/@cloudflare/workerd-linux-64/-/"
    "workerd-linux-64-1.20260807.2.tgz"
)
_PINNED_NPM_SRI = (
    "sha512-7gr33+oKGTAUArVh4Mzuo0W2bl9DZrxrkoHCinUNymtauhCACY3woVtm4V6JdkPWs"
    "niCXkIdViWu+8d8XdbleQ=="
)
_PINNED_ARCHIVE_SHA256 = (
    "e71b8e0cdb3557c021c9b2c837dfcf160ee544b6b0e04ce15f27968ac407d5e5"
)
_PINNED_BINARY_SHA256 = (
    "65f9d58baa1eb9ea04614ae6b93826fa7fd72626778e6d236d4fec4e9e8cbfa6"
)
_PINNED_UNPACKED_BYTES = 150_982_613
_PINNED_ENTRIES = (
    "package/bin/workerd",
    "package/package.json",
    "package/README.md",
)
_PINNED_BINARY_PATH = "package/bin/workerd"
_PINNED_OCI_INDEX_DIGEST = (
    "sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"
)
_PINNED_AMD64_MANIFEST_DIGEST = (
    "sha256:362e64223cc0da95422b3b13c045186fc0a81250e765d31c025fbddf257f6143"
)


class ArtifactError(RuntimeError):
    """The pinned artifact, manifest, archive, or destination was unsafe."""


@dataclasses.dataclass(frozen=True)
class ArtifactManifest:
    package_name: str
    version: str
    url: str
    npm_sri: str
    archive_sha512: bytes
    archive_sha256: str
    archive_size_bytes_max: int
    unpacked_size_bytes: int
    entry_count_max: int
    entry_size_bytes_max: int
    expected_entries: tuple[str, ...]
    binary_path: str
    binary_sha256: str
    binary_mode: int


@dataclasses.dataclass(frozen=True)
class ContainerManifest:
    base_image: str
    oci_index_digest: str
    linux_amd64_manifest_digest: str
    uid: int
    gid: int
    port: int


@dataclasses.dataclass(frozen=True)
class Manifest:
    schema_version: int
    artifact: ArtifactManifest
    container: ContainerManifest


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ArtifactError(f"download redirect rejected: HTTP {code}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ArtifactError(f"non-standard JSON value rejected: {value}")


def _decode_json(data: bytes) -> object:
    if len(data) > _MANIFEST_BYTES_MAX:
        raise ArtifactError("manifest exceeds its byte limit")
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactError(f"invalid manifest JSON: {error}") from error


def _object(value: object, label: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        raise ArtifactError(
            f"{label} has an invalid field set; missing={missing}, unknown={unknown}"
        )
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ArtifactError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ArtifactError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _exact(value: object, expected: object, label: str) -> None:
    if value != expected:
        raise ArtifactError(f"{label} does not identify the pinned artifact")


def _sha256(value: object, label: str) -> str:
    digest = _string(value, label)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ArtifactError(f"{label} must be a lowercase SHA-256 hex digest")
    return digest


def _oci_digest(value: object, label: str) -> str:
    digest = _string(value, label)
    if not digest.startswith("sha256:"):
        raise ArtifactError(f"{label} must use SHA-256")
    _sha256(digest.removeprefix("sha256:"), label)
    return digest


def _sri_sha512(value: object) -> tuple[str, bytes]:
    sri = _string(value, "artifact.npm_sri")
    algorithm, separator, encoded = sri.partition("-")
    if algorithm != "sha512" or separator != "-" or not encoded:
        raise ArtifactError("artifact.npm_sri must be one canonical SHA-512 SRI")
    try:
        digest = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ArtifactError("artifact.npm_sri has invalid base64") from error
    if len(digest) != hashlib.sha512().digest_size:
        raise ArtifactError("artifact.npm_sri has the wrong SHA-512 length")
    if base64.b64encode(digest).decode("ascii") != encoded:
        raise ArtifactError("artifact.npm_sri is not canonical base64")
    return sri, digest


def _parse_manifest(document: object) -> Manifest:
    root = _object(document, "manifest", {"schema_version", "artifact", "container"})
    schema_version = _integer(root["schema_version"], "schema_version", 1, 1)

    artifact = _object(
        root["artifact"],
        "artifact",
        {
            "package_name",
            "version",
            "url",
            "npm_sri",
            "archive_sha256",
            "archive_size_bytes_max",
            "unpacked_size_bytes",
            "entry_count_max",
            "entry_size_bytes_max",
            "expected_entries",
            "binary",
        },
    )
    package_name = _string(artifact["package_name"], "artifact.package_name")
    version = _string(artifact["version"], "artifact.version")
    url = _string(artifact["url"], "artifact.url")
    npm_sri, archive_sha512 = _sri_sha512(artifact["npm_sri"])
    archive_sha256 = _sha256(artifact["archive_sha256"], "artifact.archive_sha256")
    archive_size_bytes_max = _integer(
        artifact["archive_size_bytes_max"],
        "artifact.archive_size_bytes_max",
        1,
        128 * 1024 * 1024,
    )
    unpacked_size_bytes = _integer(
        artifact["unpacked_size_bytes"],
        "artifact.unpacked_size_bytes",
        1,
        192 * 1024 * 1024,
    )
    entry_count_max = _integer(
        artifact["entry_count_max"], "artifact.entry_count_max", 1, 8
    )
    entry_size_bytes_max = _integer(
        artifact["entry_size_bytes_max"],
        "artifact.entry_size_bytes_max",
        1,
        unpacked_size_bytes,
    )

    entries_value = artifact["expected_entries"]
    if not isinstance(entries_value, list):
        raise ArtifactError("artifact.expected_entries must be an array")
    expected_entries = tuple(
        _string(entry, f"artifact.expected_entries[{index}]")
        for index, entry in enumerate(entries_value)
    )
    if len(expected_entries) != len(set(expected_entries)):
        raise ArtifactError("artifact.expected_entries contains a duplicate")
    if len(expected_entries) > entry_count_max:
        raise ArtifactError("artifact.expected_entries exceeds entry_count_max")

    binary = _object(
        artifact["binary"], "artifact.binary", {"path", "sha256", "mode"}
    )
    binary_path = _string(binary["path"], "artifact.binary.path")
    binary_sha256 = _sha256(binary["sha256"], "artifact.binary.sha256")
    binary_mode_text = _string(binary["mode"], "artifact.binary.mode")
    if binary_mode_text != "0555":
        raise ArtifactError("artifact.binary.mode must be 0555")

    _exact(package_name, _PINNED_PACKAGE, "artifact.package_name")
    _exact(version, _PINNED_VERSION, "artifact.version")
    _exact(url, _PINNED_URL, "artifact.url")
    _exact(npm_sri, _PINNED_NPM_SRI, "artifact.npm_sri")
    _exact(archive_sha256, _PINNED_ARCHIVE_SHA256, "artifact.archive_sha256")
    _exact(unpacked_size_bytes, _PINNED_UNPACKED_BYTES, "artifact.unpacked_size_bytes")
    _exact(expected_entries, _PINNED_ENTRIES, "artifact.expected_entries")
    _exact(entry_count_max, len(_PINNED_ENTRIES), "artifact.entry_count_max")
    _exact(binary_path, _PINNED_BINARY_PATH, "artifact.binary.path")
    _exact(binary_sha256, _PINNED_BINARY_SHA256, "artifact.binary.sha256")

    container = _object(
        root["container"],
        "container",
        {
            "base_image",
            "oci_index_digest",
            "linux_amd64_manifest_digest",
            "uid",
            "gid",
            "port",
        },
    )
    base_image = _string(container["base_image"], "container.base_image")
    oci_index_digest = _oci_digest(
        container["oci_index_digest"], "container.oci_index_digest"
    )
    amd64_manifest_digest = _oci_digest(
        container["linux_amd64_manifest_digest"],
        "container.linux_amd64_manifest_digest",
    )
    uid = _integer(container["uid"], "container.uid", 1, 2**31 - 1)
    gid = _integer(container["gid"], "container.gid", 1, 2**31 - 1)
    port = _integer(container["port"], "container.port", 1, 65535)
    _exact(base_image, "docker.io/library/debian:bookworm-slim", "container.base_image")
    _exact(oci_index_digest, _PINNED_OCI_INDEX_DIGEST, "container.oci_index_digest")
    _exact(
        amd64_manifest_digest,
        _PINNED_AMD64_MANIFEST_DIGEST,
        "container.linux_amd64_manifest_digest",
    )
    _exact(uid, 65532, "container.uid")
    _exact(gid, 65532, "container.gid")
    _exact(port, 8787, "container.port")

    return Manifest(
        schema_version=schema_version,
        artifact=ArtifactManifest(
            package_name=package_name,
            version=version,
            url=url,
            npm_sri=npm_sri,
            archive_sha512=archive_sha512,
            archive_sha256=archive_sha256,
            archive_size_bytes_max=archive_size_bytes_max,
            unpacked_size_bytes=unpacked_size_bytes,
            entry_count_max=entry_count_max,
            entry_size_bytes_max=entry_size_bytes_max,
            expected_entries=expected_entries,
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            binary_mode=0o555,
        ),
        container=ContainerManifest(
            base_image=base_image,
            oci_index_digest=oci_index_digest,
            linux_amd64_manifest_digest=amd64_manifest_digest,
            uid=uid,
            gid=gid,
            port=port,
        ),
    )


def load_manifest() -> Manifest:
    try:
        manifest_stat = MANIFEST_PATH.lstat()
        if not stat.S_ISREG(manifest_stat.st_mode):
            raise ArtifactError("the pinned manifest must be a regular file")
        return _parse_manifest(_decode_json(MANIFEST_PATH.read_bytes()))
    except OSError as error:
        raise ArtifactError(f"cannot read pinned manifest: {error}") from error


def _verify_digests(
    sha512_digest: bytes, sha256_hexdigest: str, artifact: ArtifactManifest
) -> None:
    if not hmac.compare_digest(sha512_digest, artifact.archive_sha512):
        raise ArtifactError("archive SHA-512 SRI mismatch")
    if not hmac.compare_digest(sha256_hexdigest, artifact.archive_sha256):
        raise ArtifactError("archive SHA-256 mismatch")


def _fetch_archive(
    destination: Path,
    artifact: ArtifactManifest,
    opener: urllib.request.OpenerDirector | None = None,
) -> None:
    if artifact.url != _PINNED_URL:
        raise ArtifactError("refusing a URL other than the pinned HTTPS URL")
    request = urllib.request.Request(
        artifact.url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "glove-pinned-workerd-fetch/1",
        },
        method="GET",
    )
    active_opener = opener or urllib.request.build_opener(_RejectRedirects())
    sha512 = hashlib.sha512()
    sha256 = hashlib.sha256()
    total = 0

    try:
        with active_opener.open(request, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:
            if response.geturl() != artifact.url:
                raise ArtifactError("download final URL differs from the pinned URL")
            status_code = getattr(response, "status", None)
            if status_code != 200:
                raise ArtifactError(f"download returned HTTP status {status_code}")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                if not content_length.isascii() or not content_length.isdecimal():
                    raise ArtifactError("invalid Content-Length")
                if int(content_length) > artifact.archive_size_bytes_max:
                    raise ArtifactError("archive exceeds its download byte limit")

            with destination.open("wb") as output:
                os.chmod(destination, 0o600, follow_symlinks=False)
                while True:
                    remaining_probe = artifact.archive_size_bytes_max - total + 1
                    chunk = response.read(min(_DOWNLOAD_CHUNK_BYTES, remaining_probe))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > artifact.archive_size_bytes_max:
                        raise ArtifactError("archive exceeds its download byte limit")
                    sha512.update(chunk)
                    sha256.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
    except ArtifactError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise ArtifactError(f"artifact download failed: {error}") from error

    _verify_digests(sha512.digest(), sha256.hexdigest(), artifact)


def _open_regular_file(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise ArtifactError("archive must be a regular file")
        return os.fdopen(descriptor, "rb", closefd=True)
    except OSError as error:
        raise ArtifactError(f"cannot open archive safely: {error}") from error


def _verify_archive_stream(stream: BinaryIO, artifact: ArtifactManifest) -> None:
    initial = os.fstat(stream.fileno())
    if initial.st_size > artifact.archive_size_bytes_max:
        raise ArtifactError("archive exceeds its download byte limit")

    sha512 = hashlib.sha512()
    sha256 = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(_DOWNLOAD_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > artifact.archive_size_bytes_max:
            raise ArtifactError("archive exceeds its download byte limit")
        sha512.update(chunk)
        sha256.update(chunk)

    final = os.fstat(stream.fileno())
    if total != initial.st_size or final.st_size != initial.st_size:
        raise ArtifactError("archive changed while it was being verified")
    _verify_digests(sha512.digest(), sha256.hexdigest(), artifact)
    stream.seek(0)


def _safe_member_name(name: str) -> None:
    if not name or "\x00" in name or "\\" in name:
        raise ArtifactError("archive entry has an ambiguous path")
    path = PurePosixPath(name)
    parts = name.split("/")
    if path.is_absolute() or name.startswith("/"):
        raise ArtifactError(f"absolute archive entry rejected: {name!r}")
    if any(part in {"", ".", ".."} for part in parts):
        raise ArtifactError(f"traversal or ambiguous archive entry rejected: {name!r}")
    if ":" in parts[0] or any(ord(character) < 32 for character in name):
        raise ArtifactError(f"archive entry path rejected: {name!r}")


def _validate_member_type(member: tarfile.TarInfo) -> None:
    if member.issym() or member.islnk():
        raise ArtifactError(f"archive link rejected: {member.name!r}")
    if member.ischr() or member.isblk():
        raise ArtifactError(f"archive device rejected: {member.name!r}")
    if member.isfifo():
        raise ArtifactError(f"archive FIFO rejected: {member.name!r}")
    if not member.isreg():
        raise ArtifactError(f"non-regular archive entry rejected: {member.name!r}")
    if getattr(member, "sparse", None) is not None:
        raise ArtifactError(f"sparse archive entry rejected: {member.name!r}")


def _inspect_archive(stream: BinaryIO, artifact: ArtifactManifest) -> int:
    expected = set(artifact.expected_entries)
    seen: set[str] = set()
    folded_names: dict[str, str] = {}
    unpacked_bytes = 0
    binary_size = -1

    try:
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                if len(seen) >= artifact.entry_count_max:
                    raise ArtifactError("archive exceeds its entry-count limit")
                _safe_member_name(member.name)
                folded = unicodedata.normalize("NFC", member.name).casefold()
                if member.name in seen:
                    raise ArtifactError(f"duplicate archive entry: {member.name!r}")
                if folded in folded_names:
                    raise ArtifactError(
                        "case-colliding archive entries: "
                        f"{folded_names[folded]!r} and {member.name!r}"
                    )
                seen.add(member.name)
                folded_names[folded] = member.name

                _validate_member_type(member)
                if member.name not in expected:
                    raise ArtifactError(f"unknown archive entry: {member.name!r}")
                if member.size < 0 or member.size > artifact.entry_size_bytes_max:
                    raise ArtifactError(f"oversized archive entry: {member.name!r}")
                unpacked_bytes += member.size
                if unpacked_bytes > artifact.unpacked_size_bytes:
                    raise ArtifactError("archive exceeds its unpacked byte limit")
                if member.name == artifact.binary_path:
                    binary_size = member.size
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ArtifactError(f"invalid tar archive: {error}") from error

    if seen != expected:
        missing = sorted(expected - seen)
        raise ArtifactError(f"archive is missing expected entries: {missing}")
    if unpacked_bytes != artifact.unpacked_size_bytes:
        raise ArtifactError(
            "archive unpacked size mismatch: "
            f"expected {artifact.unpacked_size_bytes}, got {unpacked_bytes}"
        )
    if binary_size < 0:
        raise ArtifactError("archive does not contain the pinned binary")
    return binary_size


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_binary_atomic(
    source: IO[bytes],
    binary_size: int,
    artifact: ArtifactManifest,
    destination: Path,
) -> None:
    destination_parent = destination.parent
    destination_parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination_parent, prefix=f".{destination.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w+b", closefd=True) as output:
            copied = 0
            while copied < binary_size:
                chunk = source.read(min(_DOWNLOAD_CHUNK_BYTES, binary_size - copied))
                if not chunk:
                    raise ArtifactError("binary payload is truncated")
                copied += len(chunk)
                if copied > binary_size:
                    raise ArtifactError("binary payload exceeds its declared size")
                output.write(chunk)
            if source.read(1):
                raise ArtifactError("binary payload exceeds its declared size")
            output.flush()
            os.fsync(output.fileno())
            output.seek(0)
            final_sha256 = hashlib.file_digest(output, "sha256").hexdigest()
            if not hmac.compare_digest(final_sha256, artifact.binary_sha256):
                raise ArtifactError("final workerd binary SHA-256 mismatch")
            os.fchmod(output.fileno(), artifact.binary_mode)
            os.fsync(output.fileno())

        try:
            os.link(temporary_path, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise ArtifactError("destination already exists; refusing to overwrite it") from error
        _fsync_directory(destination_parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def _copy_binary_from_archive(
    stream: BinaryIO,
    artifact: ArtifactManifest,
    binary_size: int,
    destination: Path,
) -> None:
    stream.seek(0)
    try:
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                if member.name != artifact.binary_path:
                    continue
                source = archive.extractfile(member)
                if source is None:
                    raise ArtifactError("workerd archive member has no file payload")
                with source:
                    _copy_binary_atomic(source, binary_size, artifact, destination)
                return
    except ArtifactError:
        raise
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ArtifactError(f"cannot copy workerd from archive: {error}") from error
    raise ArtifactError("workerd binary disappeared between archive passes")


def install_from_verified_archive(
    archive_path: Path, manifest: Manifest, destination: Path
) -> None:
    with _open_regular_file(archive_path) as stream:
        # Both archive digests are checked before the first tar header is parsed.
        _verify_archive_stream(stream, manifest.artifact)
        binary_size = _inspect_archive(stream, manifest.artifact)
        _copy_binary_from_archive(stream, manifest.artifact, binary_size, destination)


def fetch_and_install(destination: Path) -> None:
    manifest = load_manifest()
    destination_parent = destination.parent
    destination_parent.mkdir(parents=True, exist_ok=True)
    descriptor, archive_name = tempfile.mkstemp(
        dir=destination_parent, prefix=".workerd-download.", suffix=".tgz"
    )
    os.close(descriptor)
    archive_path = Path(archive_name)
    try:
        _fetch_archive(archive_path, manifest.artifact)
        install_from_verified_archive(archive_path, manifest, destination)
    finally:
        archive_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch and atomically install the one pinned workerd Linux binary."
    )
    parser.add_argument(
        "--destination",
        required=True,
        type=Path,
        help="new path at which to atomically publish the verified 0555 binary",
    )
    arguments = parser.parse_args()
    try:
        fetch_and_install(arguments.destination)
    except ArtifactError as error:
        parser.exit(1, f"fetch_workerd: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
