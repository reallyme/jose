#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check publication directories and nested archives before any upload."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tarfile
import zipfile

from check_repository_privacy import (
    Inspector, PrivacyError, Reason, protected_rules, repository_root,
    snapshot, validate_path, worktree_rules, MAX_GIT_BYTES, decode,
)

from release_payloads import ReleasePayload, publication_findings

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_DEPTH = 8
MAX_ZIP_METADATA_BYTES = 16 * 1024 * 1024
ZIP_EOCD_BYTES = 22
ZIP_COMMENT_BYTES = 65535
ZIP_ENTRY_HEADER_BYTES = 46
ARCHIVE_SUFFIXES = (".zip", ".jar", ".aar", ".crate", ".tgz", ".tar.gz", ".tar")
CRATE_ROOTS = {"reallyme-jose": "crates/jose", "reallyme-jose-proto": "crates/proto"}


def validate_zip_metadata(data: bytes) -> None:
    # ZipFile constructs its entire entry inventory before iteration. Validate
    # its byte/count bounds first rather than checking after that allocation.
    start = data.rfind(b"PK\x05\x06", max(0, len(data) - ZIP_EOCD_BYTES - ZIP_COMMENT_BYTES))
    if start < 0 or len(data) - start < ZIP_EOCD_BYTES:
        raise PrivacyError(Reason.INPUT)
    _, disk, directory_disk, on_disk, count, size, offset, comment = struct.unpack_from("<4s4H2LH", data, start)
    if (disk != 0 or directory_disk != 0 or on_disk != count or count == 65535
            or size == 0xffffffff or offset == 0xffffffff or count > MAX_ENTRIES
            or size > MAX_ZIP_METADATA_BYTES or offset + size != start
            or start + ZIP_EOCD_BYTES + comment != len(data)):
        raise PrivacyError(Reason.INPUT)
    cursor = offset
    observed = 0
    while cursor < start:
        if start - cursor < ZIP_ENTRY_HEADER_BYTES or data[cursor:cursor + 4] != b"PK\x01\x02":
            raise PrivacyError(Reason.INPUT)
        name, extra, entry_comment = struct.unpack_from("<3H", data, cursor + 28)
        cursor += ZIP_ENTRY_HEADER_BYTES + name + extra + entry_comment
        observed += 1
        if cursor > start or observed > MAX_ENTRIES:
            raise PrivacyError(Reason.INPUT)
    if observed != count:
        raise PrivacyError(Reason.INPUT)


class StrictTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive: tarfile.TarFile) -> StrictTarInfo:
        # Optimized Python decoders can bypass frombuf overrides. Intercept
        # dispatch as well, before any extended-header payload is consumed.
        if self.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise PrivacyError(Reason.INPUT)
        return super()._proc_member(archive)

    @classmethod
    def frombuf(cls, buf: bytes, encoding: str, errors: str) -> StrictTarInfo:
        member = super().frombuf(buf, encoding, errors)
        # PAX and GNU extension records can allocate their payload before the
        # archive iterator yields. Only ordinary file/directory records enter
        # publication; extended/sparse/link encodings fail closed.
        if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise PrivacyError(Reason.INPUT)
        return member


@dataclass
class Budget:
    entries: int = 0
    expanded: int = 0

    def add(self, size: int) -> None:
        self.entries += 1
        self.expanded += size
        if (size < 0 or size > MAX_MEMBER_BYTES or self.entries > MAX_ENTRIES
                or self.expanded > MAX_EXPANDED_BYTES):
            raise PrivacyError(Reason.INPUT)


def archive_name(name: str) -> bool:
    return name.lower().endswith(ARCHIVE_SUFFIXES)


def source_path(path: str, archive: str, prefix: str) -> str:
    safe = validate_path(path, directory=path.endswith("/"))
    parts = safe.rstrip("/").split("/")
    if archive.lower().endswith(".crate"):
        outer = parts[0]
        matches = [root for name, root in CRATE_ROOTS.items()
                   if outer.startswith(name + "-") and outer[len(name) + 1:len(name) + 2].isdigit()]
        if len(matches) != 1:
            raise PrivacyError(Reason.INPUT)
        if len(parts) == 1:
            return matches[0] + "/"
        safe = matches[0] + "/" + "/".join(parts[1:]) + ("/" if safe.endswith("/") else "")
    elif parts[0] == "package" and archive.lower().endswith((".tgz", ".tar.gz")):
        safe = "packages/ts/" + "/".join(parts[1:]) + ("/" if safe.endswith("/") else "")
        safe = safe.rstrip("/") + ("/" if safe.endswith("/") else "")
    elif prefix:
        safe = validate_path(prefix) + "/" + safe
    return safe


class ReleaseInspector:
    def __init__(self, root: Path, inspector: Inspector, payload: ReleasePayload | None = None) -> None:
        self.root = root.resolve()
        state = snapshot(root)
        self.rules = worktree_rules(root, state)
        self.protected = protected_rules(state.rules, self.rules)
        self.inspector = inspector
        self.budget = Budget()
        self.findings: set[str] = set()
        self.payload = payload

    def paths(self, paths: list[str], archive: str = "", prefix: str = "") -> None:
        mapped = [source_path(path, archive, prefix) for path in paths]
        self.findings.update(publication_findings(self.inspector, mapped, self.rules, self.protected, self.payload))

    def source(self, path: Path, *, directory: bool = False) -> None:
        # Publication adapters must enforce the same source-path policy as
        # artifact uploads. A clean archive cannot authorize an ignored input.
        for absolute in {path.absolute(), path.resolve(strict=True)}:
            try:
                relative = absolute.relative_to(self.root).as_posix()
            except ValueError:
                relative = "/".join(absolute.parts[1:])
            if relative != ".":
                self.paths([relative + ("/" if directory else "")])

    def archive(self, name: str, data: bytes, depth: int = 0, prefix: str = "") -> None:
        if depth > MAX_DEPTH or len(data) > MAX_ARCHIVE_BYTES:
            raise PrivacyError(Reason.INPUT)
        paths = []
        nested: list[tuple[str, bytes]] = []
        try:
            if zipfile.is_zipfile(io.BytesIO(data)):
                validate_zip_metadata(data)
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for member in archive.infolist():
                        if stat.S_ISLNK(member.external_attr >> 16) or member.flag_bits & 1:
                            raise PrivacyError(Reason.INPUT)
                        self.budget.add(member.file_size)
                        paths.append(validate_path(member.filename, directory=member.is_dir()))
                        if not member.is_dir() and archive_name(member.filename):
                            with archive.open(member) as content:
                                payload = content.read(MAX_ARCHIVE_BYTES + 1)
                            if len(payload) != member.file_size:
                                raise PrivacyError(Reason.INPUT)
                            nested.append((member.filename, payload))
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*", tarinfo=StrictTarInfo) as archive:
                    for member in archive:
                        if not (member.isfile() or member.isdir()) or member.issparse():
                            raise PrivacyError(Reason.INPUT)
                        self.budget.add(member.size)
                        path = member.name + ("/" if member.isdir() and not member.name.endswith("/") else "")
                        paths.append(validate_path(path, directory=member.isdir()))
                        if member.isfile() and archive_name(member.name):
                            content = archive.extractfile(member)
                            if content is None:
                                raise PrivacyError(Reason.INPUT)
                            with content:
                                payload = content.read(MAX_ARCHIVE_BYTES + 1)
                            if len(payload) != member.size:
                                raise PrivacyError(Reason.INPUT)
                            nested.append((member.name, payload))
        except (tarfile.TarError, zipfile.BadZipFile, RuntimeError, EOFError, OSError):
            raise PrivacyError(Reason.INPUT) from None
        self.paths(paths, name, prefix)
        # A permitted wrapper filename must never hide a forbidden nested path.
        for member_name, payload in nested:
            self.archive(member_name, payload, depth + 1)

    def file(self, path: Path, prefix: str = "") -> None:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARCHIVE_BYTES:
            raise PrivacyError(Reason.INPUT)
        self.source(path)
        if archive_name(path.name):
            with path.open("rb") as content:
                data = content.read(MAX_ARCHIVE_BYTES + 1)
            self.archive(path.name, data, prefix=prefix)
        else:
            self.budget.add(metadata.st_size)
            self.paths([path.name], prefix=prefix)

    def directory(self, root: Path, prefix: str = "") -> None:
        if root.is_symlink() or not root.is_dir():
            raise PrivacyError(Reason.INPUT)
        self.source(root, directory=True)
        paths = []
        for path in root.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise PrivacyError(Reason.INPUT)
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                self.source(path, directory=True)
                self.budget.add(0)
                paths.append(relative + "/")
            elif stat.S_ISREG(metadata.st_mode):
                self.source(path)
                self.budget.add(metadata.st_size)
                paths.append(relative)
                if archive_name(path.name):
                    self.file(path)
            else:
                raise PrivacyError(Reason.INPUT)
        self.paths(paths, prefix=prefix)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?")
    parser.add_argument("--paths-stdin", action="store_true")
    parser.add_argument("--prefix", default="")
    parser.add_argument("--release-payload", choices=[item.value for item in ReleasePayload])
    args = parser.parse_args()
    try:
        root = repository_root()
        with Inspector() as inspector:
            payload = ReleasePayload(args.release_payload) if args.release_payload else None
            check = ReleaseInspector(root, inspector, payload)
            if args.paths_stdin:
                if args.path is not None:
                    raise PrivacyError(Reason.INPUT)
                raw = sys.stdin.buffer.read(MAX_GIT_BYTES + 1)
                if len(raw) > MAX_GIT_BYTES or (raw and not raw.endswith(b"\x00")):
                    raise PrivacyError(Reason.INPUT)
                paths = [decode(value) for value in raw.split(b"\x00") if value]
                check.paths(paths, prefix=args.prefix)
            else:
                if args.path is None:
                    raise PrivacyError(Reason.INPUT)
                path = Path(args.path)
                if path.is_dir():
                    check.directory(path, args.prefix)
                else:
                    check.file(path, args.prefix)
            if check.findings:
                print(json.dumps({"reason": Reason.VIOLATION.value, "findings": sorted(check.findings)}), file=sys.stderr)
                return 1
        print("Release privacy check passed.")
        return 0
    except PrivacyError as error:
        print(error.reason.value, file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError):
        print(Reason.IO.value, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
