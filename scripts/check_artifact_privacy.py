#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Validate the exact upload-artifact input without uploading any data."""

from glob import iglob
from pathlib import Path
import json
import os
import sys

from check_repository_privacy import Inspector, PrivacyError, Reason, check_index, repository_root
from check_release_privacy import MAX_ENTRIES, ReleaseInspector
from release_payloads import ReleasePayload

MAX_PATTERN_BYTES = 65536


def check_upload(root: Path, value: str, payload: ReleasePayload | None = None) -> set[str]:
    if not value or len(value.encode("utf-8")) > MAX_PATTERN_BYTES or "\x00" in value:
        raise PrivacyError(Reason.INPUT)
    included: set[Path] = set()
    excluded: set[Path] = set()
    for line in value.splitlines():
        pattern = line.strip()
        if not pattern:
            continue
        target = excluded if pattern.startswith("!") else included
        pattern = pattern[1:] if pattern.startswith("!") else pattern
        # The uploader supports more glob dialect features than Python. Fail
        # closed instead of inspecting a smaller set than it might publish.
        if (not pattern or pattern.startswith("~")
                or any(character in pattern for character in "[]{}()!\\")):
            raise PrivacyError(Reason.INPUT)
        for match in iglob(pattern, root_dir=root, recursive=True, include_hidden=True):
            path = Path(match)
            if not path.is_absolute():
                path = root / path
            target.add(path)
            if len(included) + len(excluded) > MAX_ENTRIES:
                raise PrivacyError(Reason.INPUT)
    candidates: set[Path] = set()
    visited = 0
    for path in included:
        if path.is_symlink():
            raise PrivacyError(Reason.INPUT)
        entries = path.rglob("*") if path.is_dir() else (path,)
        for entry in entries:
            visited += 1
            if visited > MAX_ENTRIES:
                raise PrivacyError(Reason.INPUT)
            if entry.is_symlink():
                raise PrivacyError(Reason.INPUT)
            if entry.is_file() and not any(entry == skip or skip in entry.parents for skip in excluded):
                candidates.add(entry)
                if len(candidates) > MAX_ENTRIES:
                    raise PrivacyError(Reason.INPUT)
    with Inspector() as inspector:
        check = ReleaseInspector(root, inspector, payload)
        for path in sorted(candidates):
            # Ignore rules apply to the source upload path as well as the
            # artifact namespace; flattening an ignored directory is no escape.
            if any(parent.is_symlink() for parent in path.parents):
                raise PrivacyError(Reason.INPUT)
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                # Absolute runner-temporary uploads still retain their full
                # path components for protected-name and ignore checks.
                relative = "/".join(path.parts[1:])
            check.paths([relative])
            if path.is_symlink():
                raise PrivacyError(Reason.INPUT)
            if check.findings:
                continue
            check.file(path)
        return check.findings


def main() -> int:
    try:
        root = repository_root()
        selected = os.environ.get("ARTIFACT_PRIVACY_RELEASE_PAYLOAD", "")
        payload = ReleasePayload(selected) if selected else None
        findings = check_index(root) | check_upload(root, os.environ.get("ARTIFACT_PRIVACY_PATHS", ""), payload)
        if findings:
            print(json.dumps({"reason": Reason.VIOLATION.value, "findings": sorted(findings)}), file=sys.stderr)
            return 1
        print("Artifact upload privacy check passed.")
        return 0
    except PrivacyError as error:
        print(error.reason.value, file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError):
        print(Reason.IO.value, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
