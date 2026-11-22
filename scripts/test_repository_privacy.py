# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Integration tests use temporary indices; no project commits are created."""

import io
from pathlib import Path
import os
import subprocess
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from check_repository_privacy import (
    Inspector, PrivacyError, Reason,
    check_index, check_state, git, local_rules, protected_rules,
    push_revisions, snapshot, validate_path,
)
from check_release_privacy import Budget, MAX_DEPTH, MAX_ENTRIES, MAX_MEMBER_BYTES, ReleaseInspector, validate_zip_metadata
from check_artifact_privacy import check_upload
from release_payloads import ReleasePayload

POLICY = b"""# BEGIN LOCAL-ONLY PATHS
AGENTS.md
.local/
.build/
.private-state/
# END LOCAL-ONLY PATHS
target/
*.log
.env
node_modules/
dist/
**/generated/**
!public/generated/
!public/generated/**
"""


class PrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="privacy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        git(self.root, "init", "--quiet", "--template=", isolated=True)
        self.write(".gitignore", POLICY)
        self.add(".gitignore")

    def write(self, path: str, data: bytes = b"public fixture\n") -> Path:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        return file

    def add(self, *paths: str) -> None:
        git(self.root, "add", "--force", "--", *paths)

    def test_clean_index_and_generated_source_exception(self) -> None:
        self.write("public/generated/model.rs")
        self.add("public/generated/model.rs")
        self.assertEqual(check_index(self.root), set())

    def test_every_force_added_exclusion_is_rejected_without_deleting_it(self) -> None:
        paths = ["AGENTS.md", "nested/AGENTS.md", ".local/key", "nested/.build/cache",
                 "nested/.private-state/config", "target/object", "nested/tool.log",
                 ".env", "nested/node_modules/module.js", "package/dist/index.js",
                 "other/generated/model.rs"]
        for path in paths:
            self.write(path)
        self.add(*paths)
        self.assertEqual(check_index(self.root), set(paths))
        for path in paths:
            self.assertEqual((self.root / path).read_bytes(), b"public fixture\n")

    def test_private_names_cannot_be_unignored_or_case_changed(self) -> None:
        self.write("nested/.gitignore", b"!AGENTS.md\n!.private-state/\n")
        self.write("nested/AGENTS.md")
        self.write("nested/.private-state/config")
        self.write("other/agents.MD")
        self.add("nested", "other")
        findings = check_index(self.root)
        self.assertTrue({"nested/AGENTS.md", "nested/.private-state/config", "other/agents.MD"} <= findings)

    def test_trusted_base_protected_names_cannot_be_removed_by_candidate(self) -> None:
        trusted = self.root / "trusted-policy"
        (trusted / "scripts").mkdir(parents=True)
        (trusted / ".gitignore").write_bytes(POLICY)
        self.write(".gitignore", b"# Candidate removed the private-name block.\n")
        self.write(".private-state/config")
        self.add(".gitignore", ".private-state/config")
        with patch("check_repository_privacy.__file__", str(trusted / "scripts/check_repository_privacy.py")):
            self.assertIn(".private-state/config", check_index(self.root))

    def test_unstaged_negation_cannot_change_staged_policy(self) -> None:
        self.write("task.log")
        self.add("task.log")
        self.write(".gitignore", POLICY + b"!task.log\n")
        self.assertIn("task.log", check_index(self.root))

    def test_unstaged_new_ignore_file_is_respected(self) -> None:
        self.write("nested/private.data")
        self.add("nested/private.data")
        self.write("nested/.gitignore", b"*.data\n")
        self.assertIn("nested/private.data", check_index(self.root))

    def test_unstaged_new_exclusion_is_respected(self) -> None:
        self.write("private.data")
        self.add("private.data")
        self.write(".gitignore", POLICY + b"*.data\n")
        self.assertIn("private.data", check_index(self.root))

    def test_tree_check_sees_an_ignored_file_even_when_it_was_removed_later(self) -> None:
        self.write("AGENTS.md")
        self.add("AGENTS.md")
        tree = git(self.root, "write-tree").decode().strip()
        git(self.root, "rm", "--cached", "--", "AGENTS.md")
        self.assertEqual(check_index(self.root), set())
        state = snapshot(self.root, tree)
        with Inspector() as inspector:
            self.assertIn("AGENTS.md", check_state(inspector, self.root, state, protected_rules(state.rules)))
        self.assertTrue((self.root / "AGENTS.md").is_file())

    def test_nested_ignore_anchor_and_negation_use_git_semantics(self) -> None:
        self.write("nested/.gitignore", b"/cache/\n*.private\n!public.private\n")
        for path in ["nested/cache/item", "nested/hidden.private", "nested/public.private", "other/cache/item"]:
            self.write(path)
        self.add("nested", "other")
        self.assertEqual(check_index(self.root), {"nested/cache/item", "nested/hidden.private"})

    def test_personal_git_excludes_do_not_become_repository_policy(self) -> None:
        info = self.root / ".git/info"
        info.mkdir(exist_ok=True)
        (info / "exclude").write_text("public.txt\n")
        self.write("public.txt")
        self.add("public.txt")
        self.assertEqual(check_index(self.root), set())

    def test_symlinked_ignore_file_is_rejected(self) -> None:
        self.write("rules", POLICY)
        (self.root / ".gitignore").unlink()
        (self.root / ".gitignore").symlink_to("rules")
        self.add(".gitignore")
        with self.assertRaises(PrivacyError):
            check_index(self.root)

    def test_symlink_to_local_data_and_outside_repository_are_rejected(self) -> None:
        (self.root / "secret-link").symlink_to(".local/secret")
        (self.root / "outside-link").symlink_to("../outside")
        self.add("secret-link", "outside-link")
        self.assertEqual(check_index(self.root), {"secret-link", "outside-link"})

    def test_normal_public_symlink_is_allowed(self) -> None:
        self.write("LICENSE")
        (self.root / "license-link").symlink_to("LICENSE")
        self.add("LICENSE", "license-link")
        self.assertEqual(check_index(self.root), set())

    def test_newline_filename_is_checked_without_line_splitting(self) -> None:
        path = "line\nbreak.log"
        self.write(path)
        self.add(path)
        self.assertIn(path, check_index(self.root))

    def test_malformed_policy_and_unsafe_paths_fail_closed(self) -> None:
        for value in [b"# BEGIN LOCAL-ONLY PATHS\n!AGENTS.md\n# END LOCAL-ONLY PATHS",
                      b"# BEGIN LOCAL-ONLY PATHS\n# BEGIN LOCAL-ONLY PATHS\n# END LOCAL-ONLY PATHS"]:
            with self.assertRaises(PrivacyError):
                local_rules(value)
        for path in ["", "/absolute", "../outside", "x/../secret", "x//secret", "C:/secret", "x\\secret", "x\x00y"]:
            with self.assertRaises(PrivacyError):
                validate_path(path)

    def test_inherited_index_does_not_redirect_policy_sandbox(self) -> None:
        self.write("AGENTS.md")
        self.add("AGENTS.md")
        with patch.dict(os.environ, {"GIT_INDEX_FILE": str(self.root / ".git/index")}):
            self.assertIn("AGENTS.md", check_index(self.root))

    def test_push_input_validates_tags_updates_and_deletions(self) -> None:
        first, second = "1" * 40, "2" * 40
        self.assertEqual(push_revisions([f"refs/heads/main {first} refs/heads/main {second}\n",
                                         f"refs/tags/v1 {second} refs/tags/v1 {'0' * 40}\n",
                                         f"(delete) {'0' * 40} refs/heads/old {first}\n"]), (first, second))
        with self.assertRaises(PrivacyError):
            push_revisions(["malformed update\n"])
        with self.assertRaises(PrivacyError):
            push_revisions([f"refs/private/snapshot {first} refs/private/snapshot {second}\n"])
        with self.assertRaises(PrivacyError):
            push_revisions([f"refs/private/snapshot {first} refs/heads/main {second}\n"])

    def test_cli_and_installed_precommit_hook_reject_force_added_paths(self) -> None:
        source = Path(__file__).resolve().parent
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "check_repository_privacy.py").write_bytes((source / "check_repository_privacy.py").read_bytes())
        self.write("AGENTS.md")
        self.add("AGENTS.md")
        result = subprocess.run([sys_executable(), str(scripts / "check_repository_privacy.py"), "index"], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(Reason.VIOLATION.value.encode(), result.stderr)
        self.assertNotIn(b"public fixture", result.stderr)

    def install_fixture_hooks(self) -> subprocess.CompletedProcess:
        source = Path(__file__).resolve().parent
        for name in ("check_repository_privacy.py", "install_repository_hooks.py"):
            self.write("scripts/" + name, (source / name).read_bytes())
        for name in ("pre-commit", "pre-push"):
            self.write(".githooks/" + name, (source.parent / ".githooks" / name).read_bytes())
        return subprocess.run([sys_executable(), str(self.root / "scripts/install_repository_hooks.py")], cwd=self.root, capture_output=True)

    def test_installed_hooks_survive_missing_worktree_scripts_and_keep_local_files(self) -> None:
        result = self.install_fixture_hooks()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("check_repository_privacy.py", "install_repository_hooks.py"):
            (self.root / "scripts" / name).unlink()
        self.write(".private-state/config")
        self.add(".private-state/config")
        result = subprocess.run(["git", "hook", "run", "pre-commit"], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(Reason.VIOLATION.value.encode(), result.stderr)
        self.assertTrue((self.root / ".private-state/config").is_file())
        head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=self.root, capture_output=True)
        self.assertNotEqual(head.returncode, 0)

    def test_installer_preserves_an_existing_hook_configuration(self) -> None:
        git(self.root, "config", "--local", "core.hooksPath", "existing-hooks")
        self.assertEqual(self.install_fixture_hooks().returncode, 1)
        self.assertEqual(git(self.root, "config", "--get", "core.hooksPath").strip(), b"existing-hooks")

    def test_installer_preserves_existing_default_hooks(self) -> None:
        path = self.root / ".git/hooks/pre-commit"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("existing hook\n")
        self.assertEqual(self.install_fixture_hooks().returncode, 1)
        self.assertEqual(path.read_text(), "existing hook\n")

    def test_upload_source_paths_and_nested_payloads_are_both_checked(self) -> None:
        self.write("target/public.txt")
        self.assertIn("target/public.txt", check_upload(self.root, "target/public.txt"))
        self.write("publication/AGENTS.md")
        self.assertIn("publication/AGENTS.md", check_upload(self.root, "publication"))
        self.assertEqual(check_upload(self.root, "missing-output/*.json"), set())

    def test_upload_exclusions_are_respected_without_following_symlinks(self) -> None:
        self.write("publication/public.txt")
        self.write("publication/private.log")
        self.assertEqual(check_upload(self.root, "publication\n!publication/private.log"), set())
        (self.root / "linked").symlink_to("publication", target_is_directory=True)
        with self.assertRaises(PrivacyError):
            check_upload(self.root, "linked/public.txt")

    def test_unsupported_upload_globs_fail_closed(self) -> None:
        for pattern in ["publication/{public,private}.txt", "publication/[ab]*", "~/.private-state/*", "publication/!(public.txt)"]:
            with self.subTest(pattern=pattern), self.assertRaises(PrivacyError):
                check_upload(self.root, pattern)

    def test_absolute_upload_outside_checkout_retains_private_components(self) -> None:
        with tempfile.TemporaryDirectory(prefix="privacy-external-") as external:
            # Resolve system temporary-directory aliases before inspecting
            # source links; the private component is the behavior under test.
            source = Path(external).resolve() / ".private-state" / "config"
            source.parent.mkdir()
            source.write_bytes(b"synthetic fixture")
            self.assertTrue(check_upload(self.root, str(source)))
            self.assertTrue(source.is_file())

    def test_android_metadata_is_not_silently_exempted_from_build_rule(self) -> None:
        self.write(".gitignore", POLICY + b"build/\n")
        with Inspector() as inspector:
            check = self.checker(inspector)
            check.archive("library.aar", self.zip_bytes({"META-INF/com/android/build/gradle/aar-metadata.properties": b"aarFormatVersion=1.0"}))
            self.assertIn("META-INF/com/android/build/gradle/aar-metadata.properties", check.findings)

    def checker(self, inspector: Inspector) -> ReleaseInspector:
        return ReleaseInspector(self.root, inspector)

    @staticmethod
    def zip_bytes(entries: dict[str, bytes]) -> bytes:
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            for path, content in entries.items():
                archive.writestr(path, content)
        return data.getvalue()

    @staticmethod
    def tar_bytes(entries: dict[str, bytes]) -> bytes:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            for path, content in entries.items():
                info = tarfile.TarInfo(path)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return data.getvalue()

    def test_archive_and_nested_archive_cannot_hide_private_files(self) -> None:
        inner = self.zip_bytes({"nested/AGENTS.md": b"synthetic private fixture"})
        with Inspector() as inspector:
            check = self.checker(inspector)
            check.archive("wrapper.zip", self.zip_bytes({"payload.jar": inner}))
            self.assertIn("nested/AGENTS.md", check.findings)

    def test_npm_dist_is_rejected_without_a_release_capability(self) -> None:
        with Inspector() as inspector:
            check = self.checker(inspector)
            check.archive("package.tgz", self.tar_bytes({"package/dist/index.js": b"export {};"}))
            self.assertIn("packages/ts/dist/index.js", check.findings)

    def test_npm_release_capability_allows_only_reviewed_files(self) -> None:
        with Inspector() as inspector:
            check = ReleaseInspector(self.root, inspector, ReleasePayload.NPM)
            check.archive("package.tgz", self.tar_bytes({"package/dist/index.js": b"export {};"}))
            self.assertEqual(check.findings, set())
            check.archive("package.tgz", self.tar_bytes({"package/dist/unreviewed.js": b"fixture"}))
            self.assertIn("packages/ts/dist/unreviewed.js", check.findings)
            check.archive("package.tgz", self.tar_bytes({"package/dist/AGENTS.md": b"fixture"}))
            self.assertIn("packages/ts/dist/AGENTS.md", check.findings)

    def test_release_capability_never_authorizes_git_tracking(self) -> None:
        self.write("packages/ts/dist/index.js")
        self.add("packages/ts/dist/index.js")
        self.assertIn("packages/ts/dist/index.js", check_index(self.root))

    def test_release_capability_preserves_specific_and_nested_ignores(self) -> None:
        self.write(".gitignore", POLICY + b"packages/ts/dist/index.js\n")
        with Inspector() as inspector:
            check = ReleaseInspector(self.root, inspector, ReleasePayload.NPM)
            check.archive("package.tgz", self.tar_bytes({"package/dist/index.js": b"fixture"}))
            self.assertIn("packages/ts/dist/index.js", check.findings)

    def test_swift_build_output_is_scoped_and_private_payloads_fail(self) -> None:
        self.write(".gitignore", POLICY + b"build/\n")
        archive = self.write("build/swift/ReallyMeJOSEFFI.xcframework.zip",
                             self.zip_bytes({"ReallyMeJOSEFFI.xcframework/Info.plist": b"fixture"}))
        with Inspector() as inspector:
            check = ReleaseInspector(self.root, inspector, ReleasePayload.SWIFT)
            check.file(archive)
            self.assertEqual(check.findings, set())
            self.write("build/swift/private.txt")
            check.directory(archive.parent)
            self.assertIn("build/swift/private.txt", check.findings)
        archive.write_bytes(self.zip_bytes({"AGENTS.md": b"fixture"}))
        self.assertIn("AGENTS.md", check_upload(self.root, str(archive), ReleasePayload.SWIFT))

    def test_maven_release_inventory_rejects_extra_build_files(self) -> None:
        self.write(".gitignore", POLICY + b"build/\n")
        repository = self.root / "build/maven-central-upload/bundle-root"
        self.write("build/maven-central-upload/bundle-root/me/really/jose/0.5.2/jose-0.5.2.pom", b"fixture")
        with Inspector() as inspector:
            check = ReleaseInspector(self.root, inspector, ReleasePayload.MAVEN)
            check.directory(repository)
            self.assertEqual(check.findings, set())
            self.write("build/maven-central-upload/bundle-root/private.txt")
            check.directory(repository)
            self.assertIn("build/maven-central-upload/bundle-root/private.txt", check.findings)

    def test_maven_capability_admits_only_the_required_aar_build_descriptor(self) -> None:
        self.write(".gitignore", POLICY + b"build/\n")
        metadata = "META-INF/com/android/build/gradle/aar-metadata.properties"
        payload = self.zip_bytes({metadata: b"aarFormatVersion=1.0"})
        with Inspector() as inspector:
            check = ReleaseInspector(self.root, inspector, ReleasePayload.MAVEN)
            check.archive("library.aar", payload)
            self.assertEqual(check.findings, set())
            unknown = "META-INF/com/android/build/private.properties"
            check.archive("library.aar", self.zip_bytes({unknown: b"fixture"}))
            self.assertIn(unknown, check.findings)
            private = "META-INF/com/android/build/AGENTS.md"
            check.archive("library.aar", self.zip_bytes({private: b"fixture"}))
            self.assertIn(private, check.findings)
        self.write(".gitignore", POLICY + b"build/\n" + metadata.encode("utf-8") + b"\n")
        with Inspector() as inspector:
            check = ReleaseInspector(self.root, inspector, ReleasePayload.MAVEN)
            check.archive("library.aar", payload)
            self.assertIn(metadata, check.findings)

    def test_clean_payload_cannot_authorize_an_ignored_publication_source(self) -> None:
        archive = self.write("target/release.zip", self.zip_bytes({"public.txt": b"fixture"}))
        directory = self.write(".private-state/public.txt").parent
        with Inspector() as inspector:
            check = self.checker(inspector)
            check.file(archive)
            self.assertIn("target/release.zip", check.findings)
            check.directory(directory)
            self.assertIn(".private-state", check.findings)

    def test_crate_source_prefix_preserves_explicit_generated_source_exception(self) -> None:
        self.write(".gitignore", POLICY + b"!crates/proto/src/generated/\n!crates/proto/src/generated/**\n")
        payload = self.tar_bytes({"reallyme-jose-proto-1.2.3/src/generated/model.rs": b"fixture"})
        with Inspector() as inspector:
            check = self.checker(inspector)
            check.archive("reallyme-jose-proto-1.2.3.crate", payload)
            self.assertEqual(check.findings, set())

    def test_archive_traversal_and_symlinks_fail_closed(self) -> None:
        with Inspector() as inspector:
            for path in ["../AGENTS.md", "/AGENTS.md", "x\\AGENTS.md"]:
                with self.assertRaises(PrivacyError):
                    self.checker(inspector).archive("bad.zip", self.zip_bytes({path: b"fixture"}))
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as archive:
                info = zipfile.ZipInfo("link")
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                archive.writestr(info, ".local/key")
            with self.assertRaises(PrivacyError):
                self.checker(inspector).archive("bad.zip", data.getvalue())

    def test_archive_limits_and_corruption_fail_closed(self) -> None:
        with self.assertRaises(PrivacyError):
            Budget().add(MAX_MEMBER_BYTES + 1)
        with self.assertRaises(PrivacyError):
            Budget(entries=MAX_ENTRIES).add(0)
        with Inspector() as inspector:
            check = self.checker(inspector)
            with self.assertRaises(PrivacyError):
                check.archive("bad.zip", b"not an archive")
            with self.assertRaises(PrivacyError):
                check.archive("deep.zip", self.zip_bytes({"public.txt": b"ok"}), MAX_DEPTH + 1)

    def test_zip_inventory_bounds_are_checked_before_entry_allocation(self) -> None:
        payload = bytearray(self.zip_bytes({"public.txt": b"ok"}))
        end = payload.rfind(b"PK\x05\x06")
        struct.pack_into("<H", payload, end + 10, 65535)
        with self.assertRaises(PrivacyError):
            validate_zip_metadata(bytes(payload))
        payload = bytearray(self.zip_bytes({"public.txt": b"ok"}))
        end = payload.rfind(b"PK\x05\x06")
        struct.pack_into("<L", payload, end + 12, 0xffffffff)
        with self.assertRaises(PrivacyError):
            validate_zip_metadata(bytes(payload))

    def test_tar_extended_metadata_is_rejected_before_processing(self) -> None:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            entry = tarfile.TarInfo("public.txt")
            entry.pax_headers = {"comment": "metadata fixture"}
            entry.size = 2
            archive.addfile(entry, io.BytesIO(b"ok"))
        with Inspector() as inspector:
            with self.assertRaises(PrivacyError):
                self.checker(inspector).archive("extended.tgz", output.getvalue())

    def test_publication_directory_preserves_files_and_rejects_ignored_names(self) -> None:
        output = self.root / "publication"
        self.write("publication/public.txt")
        self.write("publication/AGENTS.md")
        with Inspector() as inspector:
            check = self.checker(inspector)
            check.directory(output)
            self.assertIn("AGENTS.md", check.findings)
        self.assertTrue((output / "AGENTS.md").is_file())


def sys_executable() -> str:
    import sys
    return sys.executable


if __name__ == "__main__":
    unittest.main()
