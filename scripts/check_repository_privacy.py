#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reject tracked local-only paths using Git's own ignore-pattern engine."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from typing import Iterable

MAX_GIT_BYTES = 64 * 1024 * 1024
MAX_RULE_BYTES = 1024 * 1024
MAX_PATH_BYTES = 32768
BEGIN_LOCAL = b"# BEGIN LOCAL-ONLY PATHS"
END_LOCAL = b"# END LOCAL-ONLY PATHS"
BASE_LOCAL_RULES = frozenset({"AGENTS.md", ".local/", ".build/", ".git/"})
OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class Reason(str, Enum):
    INPUT = "privacy-invalid-input"
    GIT = "privacy-git-failed"
    RULES = "privacy-invalid-ignore-policy"
    CONFLICT = "privacy-unmerged-index"
    IO = "privacy-io-failed"
    VIOLATION = "privacy-local-path-tracked"
    REF = "privacy-nonpublic-ref"


class PrivacyError(Exception):
    def __init__(self, reason: Reason) -> None:
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True)
class Entry:
    path: str
    mode: str
    oid: str


@dataclass(frozen=True)
class Snapshot:
    entries: tuple[Entry, ...]
    rules: tuple[tuple[str, bytes], ...]


def decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise PrivacyError(Reason.INPUT) from None


def validate_path(path: str, *, directory: bool = False) -> str:
    value = path[:-1] if directory and path.endswith("/") else path
    if (not value or len(value.encode("utf-8")) > MAX_PATH_BYTES
            or "\x00" in value or "\\" in value or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or re.match(r"^[A-Za-z]:", value)):
        raise PrivacyError(Reason.INPUT)
    return value + ("/" if directory else "")


def git(root: Path, *args: str, data: bytes | None = None,
        accepted: tuple[int, ...] = (0,), isolated: bool = False) -> bytes:
    env = os.environ.copy()
    if isolated:
        # A hook may inherit a temporary index or an alternate object store.
        # Never let those Git variables redirect the disposable policy sandbox.
        for key in tuple(env):
            if key.startswith("GIT_"):
                del env[key]
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    try:
        # Bound memory before reading Git output. A malicious tree or policy
        # blob must not turn a filename check into an unbounded allocation.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run(
                ["git", "-c", "core.excludesFile=" + os.devnull, "-C", str(root), *args],
                input=data, stdout=output, stderr=errors,
                env=env, check=False, timeout=60,
            )
            output.seek(0)
            payload = output.read(MAX_GIT_BYTES + 1)
    except (OSError, subprocess.TimeoutExpired):
        raise PrivacyError(Reason.GIT) from None
    if result.returncode not in accepted or len(payload) > MAX_GIT_BYTES:
        raise PrivacyError(Reason.GIT)
    return payload


def repository_root() -> Path:
    return Path(decode(git(Path.cwd(), "rev-parse", "--show-toplevel")).strip())


def rule_bytes(root: Path, entry: Entry) -> bytes:
    if entry.mode not in {"100644", "100755"}:
        raise PrivacyError(Reason.RULES)
    size = git(root, "cat-file", "-s", entry.oid).strip()
    if not size.isdigit() or int(size) > MAX_RULE_BYTES:
        raise PrivacyError(Reason.RULES)
    data = git(root, "cat-file", "blob", entry.oid)
    return data


def snapshot(root: Path, tree: str | None = None) -> Snapshot:
    if tree is None:
        records = git(root, "ls-files", "--stage", "-z")
    else:
        resolved = decode(git(root, "rev-parse", "--verify", "--end-of-options", tree + "^{tree}")).strip()
        if not OBJECT_ID.fullmatch(resolved):
            raise PrivacyError(Reason.INPUT)
        records = git(root, "ls-tree", "-r", "-z", resolved)
    entries = []
    rules = []
    for record in records.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, middle, last = decode(metadata).split(" ")
        except ValueError:
            raise PrivacyError(Reason.INPUT) from None
        if tree is None:
            oid = middle
            if last != "0":
                raise PrivacyError(Reason.CONFLICT)
        else:
            oid = last
        if not OBJECT_ID.fullmatch(oid):
            raise PrivacyError(Reason.INPUT)
        path = validate_path(decode(raw_path))
        entry = Entry(path, mode, oid)
        entries.append(entry)
        if PurePosixPath(path).name == ".gitignore":
            rules.append((path, rule_bytes(root, entry)))
    return Snapshot(tuple(entries), tuple(sorted(rules)))


def local_rules(data: bytes) -> frozenset[str]:
    lines = data.splitlines()
    if BEGIN_LOCAL not in lines:
        return BASE_LOCAL_RULES
    if lines.count(BEGIN_LOCAL) != 1 or lines.count(END_LOCAL) != 1:
        raise PrivacyError(Reason.RULES)
    start, end = lines.index(BEGIN_LOCAL), lines.index(END_LOCAL)
    if end <= start:
        raise PrivacyError(Reason.RULES)
    result = set(BASE_LOCAL_RULES)
    for line in lines[start + 1:end]:
        value = decode(line)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/?", value):
            raise PrivacyError(Reason.RULES)
        result.add(value)
    return frozenset(result)


def worktree_rules(root: Path, indexed: Snapshot) -> tuple[tuple[str, bytes], ...]:
    result = []
    candidates = {".gitignore"}
    for entry in indexed.entries:
        for parent in PurePosixPath(entry.path).parents:
            candidates.add((parent / ".gitignore").as_posix())
    for path in sorted(candidates):
        file = root / path
        if any((root / parent).is_symlink() for parent in PurePosixPath(path).parents):
            raise PrivacyError(Reason.RULES)
        if file.is_symlink():
            raise PrivacyError(Reason.RULES)
        if file.is_file():
            if file.stat().st_size > MAX_RULE_BYTES:
                raise PrivacyError(Reason.RULES)
            with file.open("rb") as source:
                data = source.read(MAX_RULE_BYTES + 1)
            if len(data) > MAX_RULE_BYTES:
                raise PrivacyError(Reason.RULES)
            result.append((path, data))
    return tuple(result)


class Inspector:
    def __init__(self) -> None:
        self.stack = ExitStack()
        self.policies: dict[tuple[tuple[str, bytes], ...], Path] = {}

    def __enter__(self) -> Inspector:
        return self

    def __exit__(self, *args: object) -> None:
        self.stack.close()

    def policy(self, rules: tuple[tuple[str, bytes], ...]) -> Path:
        if rules not in self.policies:
            root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="repository-policy-")))
            git(root, "init", "--quiet", "--template=", isolated=True)
            for path, data in rules:
                if ".git" in PurePosixPath(path).parts:
                    raise PrivacyError(Reason.RULES)
                target = root / validate_path(path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            self.policies[rules] = root
        return self.policies[rules]

    def ignored(self, paths: Iterable[str], rules: tuple[tuple[str, bytes], ...]) -> set[str]:
        candidates = tuple(paths)
        if not candidates:
            return set()
        payload = b"\x00".join(path.encode("utf-8") for path in candidates) + b"\x00"
        if len(payload) > MAX_GIT_BYTES:
            raise PrivacyError(Reason.INPUT)
        result = git(self.policy(rules), "check-ignore", "--no-index", "--stdin", "-z",
                     data=payload, accepted=(0, 1), isolated=True)
        return {decode(path).rstrip("/") for path in result.split(b"\x00") if path}

    def check(self, paths: Iterable[str], rules: tuple[tuple[str, bytes], ...],
              protected: frozenset[str]) -> set[str]:
        checked = tuple(validate_path(path, directory=path.endswith("/")) for path in paths)
        private = "\n".join(sorted(protected)).encode("utf-8") + b"\n"
        names = {rule.rstrip("/").casefold() for rule in protected}
        fixed = {path.rstrip("/") for path in checked if any(part.casefold() in names for part in PurePosixPath(path).parts)}
        return fixed | self.ignored(checked, rules) | self.ignored(checked, ((".gitignore", private),))


def protected_rules(*policies: tuple[tuple[str, bytes], ...]) -> frozenset[str]:
    result = set(BASE_LOCAL_RULES)
    # A pull-request check runs the base branch's trusted script against the
    # candidate checkout. Its protected names cannot be weakened by PR edits.
    policy_files = (Path(__file__).with_name(".gitignore"),
                    Path(__file__).resolve().parent.parent / ".gitignore")
    for policy in policy_files:
        if policy.is_symlink():
            raise PrivacyError(Reason.RULES)
        if policy.is_file():
            if policy.stat().st_size > MAX_RULE_BYTES:
                raise PrivacyError(Reason.RULES)
            with policy.open("rb") as source:
                data = source.read(MAX_RULE_BYTES + 1)
            if len(data) > MAX_RULE_BYTES:
                raise PrivacyError(Reason.RULES)
            result.update(local_rules(data))
    for rules in policies:
        for path, data in rules:
            if path == ".gitignore":
                result.update(local_rules(data))
    return frozenset(result)


def paths_of(state: Snapshot) -> tuple[str, ...]:
    return tuple(entry.path + ("/" if entry.mode == "160000" else "") for entry in state.entries)


def check_state(inspector: Inspector, root: Path, state: Snapshot,
                protected: frozenset[str]) -> set[str]:
    failures = inspector.check(paths_of(state), state.rules, protected)
    for entry in state.entries:
        if entry.mode != "120000":
            continue
        target = decode(git(root, "cat-file", "blob", entry.oid))
        if (target.startswith("/") or "\\" in target or re.match(r"^[A-Za-z]:", target)):
            failures.add(entry.path)
            continue
        normalized = os.path.normpath(str(PurePosixPath(entry.path).parent / target)).replace(os.sep, "/")
        if normalized == ".." or normalized.startswith("../"):
            failures.add(entry.path)
        elif inspector.check((normalized,), state.rules, protected):
            failures.add(entry.path)
    return failures


def check_index(root: Path) -> set[str]:
    state = snapshot(root)
    working = worktree_rules(root, state)
    head = git(root, "rev-parse", "--verify", "--quiet", "HEAD^{tree}", accepted=(0, 1, 128)).strip()
    baseline = snapshot(root, decode(head)).rules if head else ()
    old_root = dict(baseline).get(".gitignore", b"")
    new_root = dict(state.rules).get(".gitignore", b"")
    if BEGIN_LOCAL in old_root and (BEGIN_LOCAL not in new_root or not local_rules(old_root) <= local_rules(new_root)):
        raise PrivacyError(Reason.RULES)
    protected = protected_rules(state.rules, working, baseline)
    with Inspector() as inspector:
        # Neither an unstaged negation nor an unstaged exclusion may hide a
        # violation in the exact index Git will commit.
        return check_state(inspector, root, state, protected) | inspector.check(paths_of(state), working, protected)


def check_history(root: Path, revisions: Iterable[str]) -> dict[str, list[str]]:
    current = snapshot(root)
    protected = protected_rules(current.rules, worktree_rules(root, current))
    resolved = []
    for revision in revisions:
        oid = decode(git(root, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}")).strip()
        if not OBJECT_ID.fullmatch(oid):
            raise PrivacyError(Reason.INPUT)
        resolved.append(oid)
    commits = decode(git(root, "rev-list", *resolved)).splitlines()
    failures = {}
    states: dict[str, Snapshot] = {}
    trees = {}
    for commit in commits:
        tree = decode(git(root, "rev-parse", commit + "^{tree}")).strip()
        trees[commit] = tree
        if tree not in states:
            states[tree] = snapshot(root, tree)
            protected |= protected_rules(states[tree].rules)
    cache: dict[str, set[str]] = {}
    with Inspector() as inspector:
        for commit in commits:
            tree = trees[commit]
            if tree not in cache:
                state = states[tree]
                # Build-directory exclusions added after a source-tree move do
                # not retroactively erase legitimate earlier source layouts.
                # Mandatory local-only names still apply to every generation.
                cache[tree] = check_state(inspector, root, state, protected | protected_rules(state.rules))
            if cache[tree]:
                failures[commit] = sorted(cache[tree])
    return failures


def push_revisions(lines: Iterable[str]) -> tuple[str, ...]:
    revisions = []
    for line in lines:
        fields = line.split()
        if len(fields) != 4 or not OBJECT_ID.fullmatch(fields[1]) or not OBJECT_ID.fullmatch(fields[3]):
            raise PrivacyError(Reason.INPUT)
        public = ("refs/heads/", "refs/tags/")
        if not fields[2].startswith(public) or (fields[0].startswith("refs/") and not fields[0].startswith(public)):
            # Mirror pushes must not export local snapshots or tool metadata
            # merely because the referenced tree happens to pass a path check.
            raise PrivacyError(Reason.REF)
        if set(fields[1]) != {"0"}:
            revisions.append(fields[1])
    return tuple(revisions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("index", "tree", "history", "push", "paths"))
    parser.add_argument("revisions", nargs="*")
    parser.add_argument("--prefix", default="")
    args = parser.parse_args()
    try:
        root = repository_root()
        if args.mode == "index":
            if args.revisions or args.prefix:
                raise PrivacyError(Reason.INPUT)
            findings: object = sorted(check_index(root))
        elif args.mode == "tree":
            if len(args.revisions) != 1 or args.prefix:
                raise PrivacyError(Reason.INPUT)
            state = snapshot(root, args.revisions[0])
            current = snapshot(root)
            with Inspector() as inspector:
                findings = sorted(check_state(inspector, root, state, protected_rules(current.rules, worktree_rules(root, current), state.rules)))
        elif args.mode in {"history", "push"}:
            if args.prefix or (args.mode == "push" and args.revisions):
                raise PrivacyError(Reason.INPUT)
            revisions = push_revisions(sys.stdin) if args.mode == "push" else tuple(args.revisions)
            if args.mode == "history" and not revisions:
                raise PrivacyError(Reason.INPUT)
            findings = check_history(root, revisions) if revisions else {}
        else:
            if args.revisions:
                raise PrivacyError(Reason.INPUT)
            state = snapshot(root)
            rules = worktree_rules(root, state)
            raw = sys.stdin.buffer.read(MAX_GIT_BYTES + 1)
            if len(raw) > MAX_GIT_BYTES or (raw and not raw.endswith(b"\x00")):
                raise PrivacyError(Reason.INPUT)
            paths = [decode(path) for path in raw.split(b"\x00") if path]
            prefix = validate_path(args.prefix) + "/" if args.prefix else ""
            with Inspector() as inspector:
                findings = sorted(inspector.check((prefix + path for path in paths), rules, protected_rules(state.rules, rules)))
        if findings:
            print(json.dumps({"reason": Reason.VIOLATION.value, "findings": findings}, ensure_ascii=True), file=sys.stderr)
            return 1
        print("Repository privacy check passed.")
        return 0
    except PrivacyError as error:
        print(error.reason.value, file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print(Reason.IO.value, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
