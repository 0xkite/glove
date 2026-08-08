#!/usr/bin/env python3
"""Synthetic, network-free tests for the pinned workerd supply-chain tool."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tarfile
import tempfile
import types
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPOSITORY_ROOT / "tools" / "fetch_workerd.py"
SPEC = importlib.util.spec_from_file_location("glove_fetch_workerd", TOOL_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {TOOL_PATH}")
fetch_workerd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fetch_workerd
SPEC.loader.exec_module(fetch_workerd)

PRODUCTION_MANIFEST = fetch_workerd.load_manifest()
EXPECTED_PATHS = (
    "package/bin/workerd",
    "package/package.json",
    "package/README.md",
)


@dataclasses.dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes = b""
    member_type: bytes = tarfile.REGTYPE
    linkname: str = ""


def make_archive(members: list[ArchiveMember]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for source_member in members:
            member = tarfile.TarInfo(source_member.name)
            member.mode = 0o777
            member.mtime = 0
            member.uid = 1234
            member.gid = 1234
            member.type = source_member.member_type
            member.linkname = source_member.linkname
            if member.isreg():
                member.size = len(source_member.data)
                archive.addfile(member, io.BytesIO(source_member.data))
            else:
                archive.addfile(member)
    return output.getvalue()


def regular_members(binary: bytes, package_json: bytes = b"{}", readme: bytes = b"readme") -> list[ArchiveMember]:
    return [
        ArchiveMember(EXPECTED_PATHS[0], binary),
        ArchiveMember(EXPECTED_PATHS[1], package_json),
        ArchiveMember(EXPECTED_PATHS[2], readme),
    ]


def synthetic_manifest(
    archive: bytes,
    binary: bytes,
    members: list[ArchiveMember],
    *,
    archive_limit: int | None = None,
    unpacked_size: int | None = None,
    entry_limit: int | None = None,
    entry_size_limit: int | None = None,
) -> types.SimpleNamespace:
    regular_sizes = [len(member.data) for member in members if member.member_type in {tarfile.REGTYPE, tarfile.AREGTYPE}]
    total_unpacked = sum(regular_sizes) if unpacked_size is None else unpacked_size
    maximum_entry = max(regular_sizes, default=1)
    artifact = dataclasses.replace(
        PRODUCTION_MANIFEST.artifact,
        archive_sha512=hashlib.sha512(archive).digest(),
        archive_sha256=hashlib.sha256(archive).hexdigest(),
        archive_size_bytes_max=(len(archive) if archive_limit is None else archive_limit),
        unpacked_size_bytes=total_unpacked,
        entry_count_max=(len(members) if entry_limit is None else entry_limit),
        entry_size_bytes_max=(maximum_entry if entry_size_limit is None else entry_size_limit),
        binary_sha256=hashlib.sha256(binary).hexdigest(),
    )
    return types.SimpleNamespace(artifact=artifact)


def write_archive(directory: Path, archive: bytes) -> Path:
    path = directory / "artifact.tgz"
    path.write_bytes(archive)
    return path


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(
            (REPOSITORY_ROOT / "tools" / "workerd-linux-64.json").read_text(
                encoding="utf-8"
            )
        )

    def test_checked_in_manifest_loads_with_all_pins(self) -> None:
        manifest = PRODUCTION_MANIFEST
        self.assertEqual(manifest.schema_version, 1)
        self.assertEqual(manifest.artifact.expected_entries, EXPECTED_PATHS)
        self.assertEqual(manifest.artifact.unpacked_size_bytes, 150_982_613)
        self.assertEqual(manifest.artifact.binary_mode, 0o555)
        self.assertEqual(manifest.container.port, 8787)
        self.assertEqual(manifest.container.uid, 65532)
        self.assertEqual(manifest.container.gid, 65532)

    def test_unknown_manifest_field_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["artifact"]["hooks"] = {"postinstall": "allowed"}
        with self.assertRaisesRegex(fetch_workerd.ArtifactError, "invalid field set"):
            fetch_workerd._parse_manifest(document)

    def test_non_pinned_url_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["artifact"]["url"] = "https://example.invalid/workerd.tgz"
        with self.assertRaisesRegex(fetch_workerd.ArtifactError, "pinned artifact"):
            fetch_workerd._parse_manifest(document)

    def test_changed_digest_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["artifact"]["archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(fetch_workerd.ArtifactError, "pinned artifact"):
            fetch_workerd._parse_manifest(document)

    def test_changed_entry_list_and_unpacked_size_are_rejected(self) -> None:
        for field, replacement in (
            ("expected_entries", list(EXPECTED_PATHS[:-1])),
            ("unpacked_size_bytes", 150_982_612),
        ):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["artifact"][field] = replacement
                with self.assertRaises(fetch_workerd.ArtifactError):
                    fetch_workerd._parse_manifest(document)

    def test_duplicate_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(fetch_workerd.ArtifactError, "duplicate JSON key"):
            fetch_workerd._decode_json(b'{"schema_version":1,"schema_version":1}')

    def test_boolean_is_not_accepted_as_integer(self) -> None:
        document = copy.deepcopy(self.document)
        document["container"]["port"] = True
        with self.assertRaises(fetch_workerd.ArtifactError):
            fetch_workerd._parse_manifest(document)


class ArchiveValidationTests(unittest.TestCase):
    def install(
        self,
        root: Path,
        members: list[ArchiveMember],
        *,
        binary: bytes = b"synthetic-workerd",
        **manifest_overrides: int,
    ) -> Path:
        archive = make_archive(members)
        manifest = synthetic_manifest(
            archive, binary, members, **manifest_overrides
        )
        archive_path = write_archive(root, archive)
        destination = root / "output" / "workerd"
        fetch_workerd.install_from_verified_archive(
            archive_path, manifest, destination
        )
        return destination

    def assert_rejected(
        self,
        members: list[ArchiveMember],
        pattern: str,
        *,
        binary: bytes = b"synthetic-workerd",
        **manifest_overrides: int,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(fetch_workerd.ArtifactError, pattern):
                self.install(
                    root,
                    members,
                    binary=binary,
                    **manifest_overrides,
                )
            self.assertFalse((root / "output" / "workerd").exists())

    def test_valid_archive_copies_only_binary_with_mode_0555(self) -> None:
        binary = b"synthetic-workerd"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = self.install(root, regular_members(binary), binary=binary)
            self.assertEqual(destination.read_bytes(), binary)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)
            self.assertEqual([path.name for path in destination.parent.iterdir()], ["workerd"])

    def test_package_scripts_are_never_run(self) -> None:
        binary = b"synthetic-workerd"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sentinel = root / "PACKAGE_SCRIPT_RAN"
            package_json = json.dumps(
                {
                    "scripts": {
                        "preinstall": f"/usr/bin/touch {sentinel}",
                        "install": f"/usr/bin/touch {sentinel}",
                        "postinstall": f"/usr/bin/touch {sentinel}",
                    }
                }
            ).encode("utf-8")
            self.install(
                root,
                regular_members(binary, package_json=package_json),
                binary=binary,
            )
            self.assertFalse(sentinel.exists())

    def test_unknown_entry_is_rejected(self) -> None:
        members = regular_members(b"synthetic-workerd") + [
            ArchiveMember("package/extra", b"unexpected")
        ]
        self.assert_rejected(members, "unknown archive entry", entry_limit=4)

    def test_absolute_and_traversal_entries_are_rejected(self) -> None:
        for bad_name, pattern in (
            ("/tmp/escape", "absolute archive entry"),
            ("package/../escape", "traversal"),
            ("package//escape", "traversal"),
            ("C:/escape", "path rejected"),
            (r"package\\escape", "ambiguous path"),
        ):
            with self.subTest(name=bad_name):
                members = regular_members(b"synthetic-workerd") + [
                    ArchiveMember(bad_name, b"escape")
                ]
                self.assert_rejected(members, pattern, entry_limit=4)

    def test_links_devices_and_fifo_are_rejected(self) -> None:
        dangerous_types = (
            (tarfile.SYMTYPE, "link"),
            (tarfile.LNKTYPE, "link"),
            (tarfile.CHRTYPE, "device"),
            (tarfile.BLKTYPE, "device"),
            (tarfile.FIFOTYPE, "FIFO"),
        )
        for member_type, pattern in dangerous_types:
            with self.subTest(member_type=member_type):
                members = [
                    ArchiveMember(
                        EXPECTED_PATHS[0],
                        member_type=member_type,
                        linkname="package/package.json",
                    ),
                    ArchiveMember(EXPECTED_PATHS[1], b"{}"),
                    ArchiveMember(EXPECTED_PATHS[2], b"readme"),
                ]
                self.assert_rejected(members, pattern)

    def test_directory_is_rejected(self) -> None:
        members = regular_members(b"synthetic-workerd") + [
            ArchiveMember("package/extra", member_type=tarfile.DIRTYPE)
        ]
        self.assert_rejected(members, "non-regular", entry_limit=4)

    def test_duplicate_entry_is_rejected(self) -> None:
        members = regular_members(b"synthetic-workerd") + [
            ArchiveMember(EXPECTED_PATHS[0], b"duplicate")
        ]
        self.assert_rejected(members, "duplicate archive entry", entry_limit=4)

    def test_case_collision_is_rejected(self) -> None:
        members = regular_members(b"synthetic-workerd") + [
            ArchiveMember("PACKAGE/BIN/WORKERD", b"collision")
        ]
        self.assert_rejected(members, "case-colliding", entry_limit=4)

    def test_entry_count_limit_is_enforced_before_unknown_entry(self) -> None:
        members = regular_members(b"synthetic-workerd") + [
            ArchiveMember("package/extra", b"fourth")
        ]
        self.assert_rejected(members, "entry-count limit", entry_limit=3)

    def test_per_entry_and_total_unpacked_limits_are_enforced(self) -> None:
        binary = b"synthetic-workerd"
        members = regular_members(binary)
        self.assert_rejected(
            members,
            "oversized archive entry",
            binary=binary,
            entry_size_limit=len(binary) - 1,
        )
        actual_total = sum(len(member.data) for member in members)
        self.assert_rejected(
            members,
            "unpacked byte limit",
            binary=binary,
            unpacked_size=actual_total - 1,
        )

    def test_exact_unpacked_size_is_required(self) -> None:
        binary = b"synthetic-workerd"
        members = regular_members(binary)
        actual_total = sum(len(member.data) for member in members)
        self.assert_rejected(
            members,
            "unpacked size mismatch",
            binary=binary,
            unpacked_size=actual_total + 1,
            entry_size_limit=actual_total + 1,
        )

    def test_missing_expected_entry_is_rejected(self) -> None:
        members = regular_members(b"synthetic-workerd")[:-1]
        self.assert_rejected(members, "missing expected entries")

    def test_archive_download_size_bound_is_checked(self) -> None:
        binary = b"synthetic-workerd"
        members = regular_members(binary)
        archive = make_archive(members)
        self.assert_rejected(
            members,
            "download byte limit",
            binary=binary,
            archive_limit=len(archive) - 1,
        )

    def test_both_archive_digests_are_required_before_tar_parsing(self) -> None:
        binary = b"synthetic-workerd"
        members = regular_members(binary)
        archive = make_archive(members)
        base_manifest = synthetic_manifest(archive, binary, members)
        mutations = (
            {"archive_sha512": b"\x00" * 64},
            {"archive_sha256": "0" * 64},
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=next(iter(mutation))),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                archive_path = write_archive(root, archive)
                manifest = types.SimpleNamespace(
                    artifact=dataclasses.replace(
                        base_manifest.artifact, **mutation
                    )
                )
                with (
                    mock.patch.object(fetch_workerd.tarfile, "open") as tar_open,
                    self.assertRaisesRegex(fetch_workerd.ArtifactError, "mismatch"),
                ):
                    fetch_workerd.install_from_verified_archive(
                        archive_path, manifest, root / "workerd"
                    )
                tar_open.assert_not_called()

    def test_final_binary_hash_mismatch_leaves_no_destination(self) -> None:
        binary = b"synthetic-workerd"
        members = regular_members(binary)
        archive = make_archive(members)
        manifest = synthetic_manifest(archive, binary, members)
        manifest = types.SimpleNamespace(
            artifact=dataclasses.replace(
                manifest.artifact, binary_sha256="0" * 64
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "output" / "workerd"
            with self.assertRaisesRegex(fetch_workerd.ArtifactError, "final workerd"):
                fetch_workerd.install_from_verified_archive(
                    write_archive(root, archive), manifest, destination
                )
            self.assertFalse(destination.exists())
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])

    def test_atomic_publish_refuses_to_replace_existing_destination(self) -> None:
        binary = b"synthetic-workerd"
        members = regular_members(binary)
        archive = make_archive(members)
        manifest = synthetic_manifest(archive, binary, members)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "output" / "workerd"
            destination.parent.mkdir()
            destination.write_bytes(b"do-not-replace")
            with self.assertRaisesRegex(fetch_workerd.ArtifactError, "refusing to overwrite"):
                fetch_workerd.install_from_verified_archive(
                    write_archive(root, archive), manifest, destination
                )
            self.assertEqual(destination.read_bytes(), b"do-not-replace")
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])

    def test_generic_tar_extraction_api_is_absent(self) -> None:
        source = TOOL_PATH.read_text(encoding="utf-8")
        self.assertNotIn(".extractall", source)
        self.assertNotIn("subprocess", source)


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, url: str, *, status: int = 200, content_length: str | None = None):
        super().__init__(body)
        self._url = url
        self.status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.request: urllib.request.Request | None = None
        self.timeout: int | None = None

    def open(
        self, request: urllib.request.Request, timeout: int
    ) -> FakeResponse:
        self.request = request
        self.timeout = timeout
        return self.response


class DownloadTests(unittest.TestCase):
    def test_download_uses_only_pinned_url_and_verifies_bytes(self) -> None:
        body = b"verified compressed bytes"
        artifact = dataclasses.replace(
            PRODUCTION_MANIFEST.artifact,
            archive_sha512=hashlib.sha512(body).digest(),
            archive_sha256=hashlib.sha256(body).hexdigest(),
            archive_size_bytes_max=len(body),
        )
        response = FakeResponse(
            body, artifact.url, content_length=str(len(body))
        )
        opener = FakeOpener(response)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "download.tgz"
            fetch_workerd._fetch_archive(destination, artifact, opener)
            self.assertEqual(destination.read_bytes(), body)
            request = opener.request
            self.assertIsNotNone(request)
            assert request is not None
            self.assertEqual(request.full_url, artifact.url)
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(opener.timeout, 60)

    def test_changed_final_url_is_rejected(self) -> None:
        body = b"body"
        artifact = dataclasses.replace(
            PRODUCTION_MANIFEST.artifact,
            archive_sha512=hashlib.sha512(body).digest(),
            archive_sha256=hashlib.sha256(body).hexdigest(),
            archive_size_bytes_max=len(body),
        )
        response = FakeResponse(body, "https://example.invalid/redirected")
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(fetch_workerd.ArtifactError, "final URL"),
        ):
            fetch_workerd._fetch_archive(
                Path(temporary) / "download.tgz", artifact, FakeOpener(response)
            )

    def test_content_length_and_stream_limits_are_enforced(self) -> None:
        body = b"too large"
        artifact = dataclasses.replace(
            PRODUCTION_MANIFEST.artifact,
            archive_sha512=hashlib.sha512(body).digest(),
            archive_sha256=hashlib.sha256(body).hexdigest(),
            archive_size_bytes_max=len(body) - 1,
        )
        responses = (
            FakeResponse(body, artifact.url, content_length=str(len(body))),
            FakeResponse(body, artifact.url),
        )
        for response in responses:
            with (
                self.subTest(
                    content_length=response.headers.get("Content-Length")
                ),
                tempfile.TemporaryDirectory() as temporary,
                self.assertRaisesRegex(fetch_workerd.ArtifactError, "byte limit"),
            ):
                fetch_workerd._fetch_archive(
                    Path(temporary) / "download.tgz",
                    artifact,
                    FakeOpener(response),
                )

    def test_non_decimal_content_length_is_rejected(self) -> None:
        artifact = PRODUCTION_MANIFEST.artifact
        response = FakeResponse(b"", artifact.url, content_length="+1")
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(fetch_workerd.ArtifactError, "Content-Length"),
        ):
            fetch_workerd._fetch_archive(
                Path(temporary) / "download.tgz", artifact, FakeOpener(response)
            )


class FixtureAndDockerfileTests(unittest.TestCase):
    def test_fixture_and_container_are_fixed_to_pinned_port_and_image(self) -> None:
        dockerfile = (
            REPOSITORY_ROOT / "dockerfiles" / "Dockerfile.remote-workerd"
        ).read_text(encoding="utf-8")
        config = (
            REPOSITORY_ROOT
            / "tests"
            / "fixtures"
            / "remote-workerd"
            / "workerd.capnp"
        ).read_text(encoding="utf-8")
        module = (
            REPOSITORY_ROOT
            / "tests"
            / "fixtures"
            / "remote-workerd"
            / "hello.mjs"
        ).read_text(encoding="utf-8")

        self.assertIn(PRODUCTION_MANIFEST.container.linux_amd64_manifest_digest, dockerfile)
        self.assertIn(PRODUCTION_MANIFEST.container.oci_index_digest, dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertIn("EXPOSE 8787", dockerfile)
        self.assertIn('address = "*:8787"', config)
        self.assertIn('embed "hello.mjs"', config)
        self.assertIn('Response("Hello, World!\\n"', module)

    def test_dockerfile_has_no_network_or_package_manager_step(self) -> None:
        dockerfile = (
            REPOSITORY_ROOT / "dockerfiles" / "Dockerfile.remote-workerd"
        ).read_text(encoding="utf-8")
        lowered = dockerfile.lower()
        for forbidden in ("apt-get", "apt ", "apk ", "dnf ", "yum ", "curl ", "wget ", "add http"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)
        self.assertIn(
            "COPY --chown=65532:65532 --chmod=0555 "
            "tools/.cache/remote-workerd/workerd",
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
