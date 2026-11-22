#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reject advisories in the resolved JVM and Android dependency locks."""

from enum import Enum
import json
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

MAX_BYTES = 4194304
MAX_PACKAGES = 1000
LOCKFILES = (
    "packages/kotlin/gradle.lockfile",
    "packages/kotlin/buildscript-gradle.lockfile",
    "packages/kotlin-android/gradle.lockfile",
    "packages/kotlin-android/buildscript-gradle.lockfile",
    "packages/kotlin-android/consumer-r8-runtime/gradle.lockfile",
)
COORDINATE = re.compile(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+\Z")
VERSION = re.compile(r"[A-Za-z0-9_.+\[\],()-]+\Z")
ADVISORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{4,127}\Z")


class AdvisoryReason(str, Enum):
    INPUT = "jvm-advisory-invalid-lockfile"
    IO = "jvm-advisory-input-unreadable"
    NETWORK = "jvm-advisory-service-unavailable"
    RESPONSE = "jvm-advisory-invalid-response"
    VULNERABLE = "jvm-advisory-vulnerable-dependency"


class AdvisoryError(Exception):
    def __init__(self, reason: AdvisoryReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def parse_locks(sources: list[str]) -> list[dict[str, object]]:
    packages = set()
    for source in sources:
        populated = False
        for line in source.splitlines():
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coordinate, separator, configurations = line.partition("=")
            parts = coordinate.split(":")
            if len(parts) != 3 or not separator or not configurations:
                raise AdvisoryError(AdvisoryReason.INPUT)
            name, version = ":".join(parts[:2]), parts[2]
            if not COORDINATE.fullmatch(name) or not VERSION.fullmatch(version) or len(version) > 128:
                raise AdvisoryError(AdvisoryReason.INPUT)
            populated = True
            packages.add((name, version))
            if len(packages) > MAX_PACKAGES:
                raise AdvisoryError(AdvisoryReason.INPUT)
        if not populated:
            raise AdvisoryError(AdvisoryReason.INPUT)
    if not packages:
        raise AdvisoryError(AdvisoryReason.INPUT)
    return [{"package": {"ecosystem": "Maven", "name": name}, "version": version}
            for name, version in sorted(packages)]


def findings(queries: list[dict[str, object]], response: object) -> list[dict[str, object]]:
    if not isinstance(response, dict) or not isinstance(response.get("results"), list):
        raise AdvisoryError(AdvisoryReason.RESPONSE)
    results = response["results"]
    if len(results) != len(queries):
        raise AdvisoryError(AdvisoryReason.RESPONSE)
    failures = []
    for query, result in zip(queries, results):
        if (not isinstance(result, dict) or "error" in result or "errors" in result
                or result.get("next_page_token") or result.get("nextPageToken")):
            raise AdvisoryError(AdvisoryReason.RESPONSE)
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise AdvisoryError(AdvisoryReason.RESPONSE)
        ids = []
        for vulnerability in vulnerabilities:
            if (not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str)
                    or not ADVISORY.fullmatch(vulnerability["id"])):
                raise AdvisoryError(AdvisoryReason.RESPONSE)
            ids.append(vulnerability["id"])
        if ids:
            failures.append({"package": query["package"], "version": query["version"], "advisories": ids})
    return failures


def query_registry(queries: list[dict[str, object]]) -> object:
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise AdvisoryError(AdvisoryReason.RESPONSE)
            try:
                return json.loads(raw)
            except (UnicodeError, ValueError):
                raise AdvisoryError(AdvisoryReason.RESPONSE) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 2:
                raise AdvisoryError(AdvisoryReason.NETWORK) from None
            time.sleep(2 ** attempt)
    raise AdvisoryError(AdvisoryReason.NETWORK)


def read_locks(root: Path) -> list[str]:
    try:
        sources = []
        for name in LOCKFILES:
            path = root / name
            if path.is_symlink():
                raise AdvisoryError(AdvisoryReason.INPUT)
            with path.open("rb") as source:
                data = source.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise AdvisoryError(AdvisoryReason.INPUT)
            sources.append(data.decode("utf-8"))
        return sources
    except OSError:
        raise AdvisoryError(AdvisoryReason.IO) from None
    except UnicodeError:
        raise AdvisoryError(AdvisoryReason.INPUT) from None


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        queries = parse_locks(read_locks(root))
        vulnerable = findings(queries, query_registry(queries))
        if vulnerable:
            print(json.dumps({"reason": AdvisoryReason.VULNERABLE.value, "dependencies": vulnerable}), file=sys.stderr)
            return 1
        print(f"JVM advisory check passed: {len(queries)} locked packages, no advisories.")
        return 0
    except AdvisoryError as error:
        print(error.reason.value, file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print(AdvisoryReason.IO.value, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
