// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const scriptPath = join(repositoryRoot, "scripts/write_native_manifest.mjs");

test("native manifest writes matching bounded loader metadata", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "reallyme-native-manifest-"));
  try {
    const nativeRoot = join(temporaryRoot, "native");
    const libraryPath = join(nativeRoot, "linux-x86_64/libreallyme_jose_ffi.so");
    const manifestPath = join(nativeRoot, "native-manifest.json");
    const libraryBytes = Buffer.from("deterministic native fixture", "utf8");
    mkdirSync(dirname(libraryPath), { recursive: true });
    writeFileSync(libraryPath, libraryBytes);

    execFileSync(process.execPath, [scriptPath, nativeRoot, manifestPath], {
      cwd: repositoryRoot,
      stdio: "pipe",
    });

    const expectedDigest = createHash("sha256").update(libraryBytes).digest("hex");
    assert.equal(
      readFileSync(`${libraryPath}.sha256`, "utf8"),
      `${expectedDigest} ${libraryBytes.length}\n`,
    );
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    assert.equal(manifest.schemaVersion, 1);
    assert.equal(manifest.package, "reallyme-jose-native");
    assert.match(manifest.commitSha, /^[0-9a-f]{40}$/u);
    assert.deepEqual(manifest.entries, [
      {
        path: "linux-x86_64/libreallyme_jose_ffi.so",
        sha256: expectedDigest,
        size: libraryBytes.length,
      },
    ]);

    // A second run must ignore its own sidecar and reproduce the same manifest.
    const firstManifest = readFileSync(manifestPath);
    execFileSync(process.execPath, [scriptPath, nativeRoot, manifestPath], {
      cwd: repositoryRoot,
      stdio: "pipe",
    });
    assert.deepEqual(readFileSync(manifestPath), firstManifest);

    assert.throws(() => {
      execFileSync(process.execPath, [scriptPath, nativeRoot, manifestPath], {
        cwd: repositoryRoot,
        env: { ...process.env, GITHUB_SHA: "0".repeat(40) },
        stdio: "pipe",
      });
    });
  } finally {
    rmSync(temporaryRoot, { force: true, recursive: true });
  }
});
