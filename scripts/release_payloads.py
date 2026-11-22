# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reviewed compiler outputs are publication capabilities, never tracking exceptions."""

from enum import Enum
import json
from pathlib import Path
import re

from check_repository_privacy import Inspector, PrivacyError, Reason, validate_path


class ReleasePayload(str, Enum):
    NPM = "npm"
    SWIFT = "swift"
    MAVEN = "maven"
    CRATES = "crates"
    NATIVE = "native"


BUILD_CONTAINERS = frozenset({b"/target", b"/target/", b"target/", b"**/target/",
                              b"dist/", b"build/", b"**/build/"})
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
PLATFORMS = frozenset({"linux-x86_64", "linux-aarch64", "macos-x86_64",
                       "macos-aarch64", "windows-x86_64"})
MAVEN_FILE = re.compile(
    r"me/really/(?P<name>jose|jose-android)/(?P<version>" + VERSION +
    r")/(?P=name)-(?P=version)(?:-(?:sources|javadoc))?\.(?:jar|aar|pom|module)"
    r"(?:\.asc)?(?:\.(?:sha256|sha512|sha1|md5))?\Z")


def npm_files() -> frozenset[str]:
    policy = Path(__file__).with_name("publication_payloads.json")
    try:
        if policy.is_symlink():
            raise PrivacyError(Reason.RULES)
        with policy.open("rb") as source:
            data = source.read(16385)
        if len(data) > 16384:
            raise PrivacyError(Reason.RULES)
        value = json.loads(data)
        if (not isinstance(value, dict) or set(value) != {"schema", "npm"}
                or value["schema"] != 1 or not isinstance(value["npm"], list)
                or any(not isinstance(path, str) for path in value["npm"])):
            raise PrivacyError(Reason.RULES)
        paths = frozenset(validate_path(path) for path in value["npm"])
        if len(paths) != len(value["npm"]):
            raise PrivacyError(Reason.RULES)
        return paths
    except (OSError, UnicodeError, ValueError):
        raise PrivacyError(Reason.RULES) from None


def reviewed_output(path: str, payload: ReleasePayload) -> bool:
    directory = path.endswith("/")
    path = path.rstrip("/")
    if payload == ReleasePayload.NPM and path.startswith("packages/ts/"):
        if path == "packages/ts/dist":
            return directory
        relative = path[len("packages/ts/"):]
        return any(item.startswith(relative + "/") for item in npm_files()) if directory else relative in npm_files()
    # A directory capability admits only its root. Every descendant is checked
    # separately against this inventory before an archive can be uploaded.
    if directory and path in {
        "build/crate-release", "build/maven-release",
        "build/maven-central-upload/bundle-root", "build/kotlin-native-resources",
        "build/kotlin-native-digests", "build/swift", "build/npm",
    }:
        return True
    if payload == ReleasePayload.SWIFT:
        return path.startswith("build/") and Path(path).name in {
            "ReallyMeJOSEFFI.xcframework.zip", "ReallyMeJOSEFFI.xcframework.checksum"}
    if payload == ReleasePayload.CRATES:
        return ((path.startswith("build/") or path.startswith("target/package/")) and
                (re.fullmatch(r"reallyme-jose(?:-proto)?-" + VERSION + r"\.crate", Path(path).name)
                 is not None or Path(path).name == "crate-archives.json"))
    if payload == ReleasePayload.NPM:
        return path.startswith("build/npm/") and re.fullmatch(
            r"reallyme-jose-" + VERSION + r"\.tgz(?:\.sha256)?", Path(path).name) is not None
    if payload == ReleasePayload.MAVEN:
        # AGP's required AAR metadata uses a package component named build.
        # This exact compiled descriptor is distinct from arbitrary build output.
        metadata = "META-INF/com/android/build/gradle/aar-metadata.properties"
        if path == metadata or (directory and metadata.startswith(path + "/")):
            return True
        for prefix in ["build/maven-release/", "build/maven-central-upload/bundle-root/"]:
            if path.startswith(prefix):
                relative = path[len(prefix):]
                if directory:
                    return relative in {"me", "me/really", "me/really/jose", "me/really/jose-android"} or \
                        re.fullmatch(r"me/really/(?:jose|jose-android)/" + VERSION, relative) is not None
                return MAVEN_FILE.fullmatch(relative) is not None or re.fullmatch(
                    r"me/really/(?:jose|jose-android)/maven-metadata\.xml(?:\.(?:sha256|sha512|sha1|md5))?",
                    relative) is not None
    if payload == ReleasePayload.NATIVE:
        prefix = "build/kotlin-native-resources/"
        if path.startswith(prefix):
            relative = path[len(prefix):]
            if directory:
                return relative in {"me", "me/really", "me/really/jose", "me/really/jose/native"} or \
                    relative in {"me/really/jose/native/" + item for item in PLATFORMS}
            for platform in PLATFORMS:
                library = "reallyme_jose_ffi.dll" if platform.startswith("windows-") else \
                    "libreallyme_jose_ffi.dylib" if platform.startswith("macos-") else "libreallyme_jose_ffi.so"
                if relative == "me/really/jose/native/" + platform + "/" + library:
                    return True
        return path.startswith("build/kotlin-native-digests/") and \
            Path(path).name in {item + ".sha256" for item in PLATFORMS}
    return False


def publication_findings(inspector: Inspector, paths: list[str], rules: tuple[tuple[str, bytes], ...],
                         protected: frozenset[str], payload: ReleasePayload | None) -> set[str]:
    failures = inspector.check(paths, rules, protected)
    if payload is None:
        return failures
    candidates = [path for path in paths if path.rstrip("/") in failures and reviewed_output(path, payload)]
    # Only the root's generic compiler-output containers can be exempted. All
    # private patterns, nested ignores, symlink rules, and protected names still
    # apply, even when a caller supplies a release capability.
    containers = BUILD_CONTAINERS | (frozenset({b"**/generated", b"**/generated/**"})
                                     if payload == ReleasePayload.NPM else frozenset())
    filtered = tuple((name, b"\n".join(line for line in data.splitlines()
                                     if line.strip() not in containers) + b"\n")
                     if name == ".gitignore" else (name, data) for name, data in rules)
    rejected = inspector.check(candidates, filtered, protected)
    return failures - {path.rstrip("/") for path in candidates if path.rstrip("/") not in rejected}
