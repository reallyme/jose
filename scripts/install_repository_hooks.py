#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Install repository privacy hooks without replacing an existing hook setup."""

from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

from check_repository_privacy import BEGIN_LOCAL, END_LOCAL, PrivacyError, local_rules


def main() -> int:
    try:
        root_result = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=False)
        if root_result.returncode != 0:
            return 2
        root = Path(root_result.stdout.decode("utf-8").strip())
        common = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=root, capture_output=True, check=False)
        if common.returncode != 0:
            return 2
        common_directory = Path(common.stdout.decode("utf-8").strip())
        if not common_directory.is_absolute():
            common_directory = root / common_directory
        destination = common_directory.resolve() / "privacy-hooks"
        configured = subprocess.run(["git", "config", "--get", "core.hooksPath"], cwd=root, capture_output=True, check=False)
        if configured.returncode not in (0, 1):
            return 2
        if configured.returncode == 0 and configured.stdout.decode("utf-8").strip() != str(destination):
            print("Existing hooksPath retained; chain the privacy hooks before installation.", file=sys.stderr)
            return 1
        default = subprocess.run(["git", "rev-parse", "--git-path", "hooks"], cwd=root, capture_output=True, check=False)
        if default.returncode != 0:
            return 2
        hook_directory = Path(default.stdout.decode("utf-8").strip())
        if not hook_directory.is_absolute():
            hook_directory = root / hook_directory
        if configured.returncode == 1 and any((hook_directory / name).exists() for name in ("pre-commit", "pre-push")):
            print("Existing default hooks retained; chain the privacy hooks before installation.", file=sys.stderr)
            return 1
        if destination.is_symlink() or (destination.exists() and not (destination / "installed.json").is_file()):
            print("Existing local hook directory retained.", file=sys.stderr)
            return 1
        if any((destination / name).is_symlink() for name in (".gitignore", "installed.json", "pre-commit", "pre-push", "check_repository_privacy.py")):
            return 1
        rules = local_rules((root / ".gitignore").read_bytes())
        if (destination / ".gitignore").is_file():
            rules |= local_rules((destination / ".gitignore").read_bytes())
        files = {name: root / ".githooks" / name for name in ("pre-commit", "pre-push")}
        files["check_repository_privacy.py"] = root / "scripts/check_repository_privacy.py"
        if any(not path.is_file() or path.is_symlink() for path in files.values()):
            return 2
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, source in files.items():
            temporary = destination / (name + ".new")
            if temporary.exists() or temporary.is_symlink():
                return 2
            shutil.copyfile(source, temporary)
            temporary.chmod(0o700)
            os.replace(temporary, destination / name)
        policy = BEGIN_LOCAL + b"\n" + "\n".join(sorted(rules)).encode("utf-8") + b"\n" + END_LOCAL + b"\n"
        (destination / ".gitignore").write_bytes(policy)
        (destination / "installed.json").write_text(json.dumps({"schema": 1}) + "\n")
        # The shared Git directory survives branch switches and is used by all
        # linked worktrees, including older branches without these scripts.
        subprocess.run(["git", "config", "--local", "core.hooksPath", str(destination)], cwd=root, check=True)
        print("Repository pre-commit and pre-push privacy hooks installed.")
        return 0
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        print("privacy-hook-install-failed", file=sys.stderr)
        return 2
    except PrivacyError:
        print("privacy-hook-install-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
