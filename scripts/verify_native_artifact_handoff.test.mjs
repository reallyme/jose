#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./verify_native_artifact_handoff.mjs", import.meta.url));
const resources = [
  ["linux-x86_64/libreallyme_jose_ffi.so", "linux-x86_64.sha256"],
  ["linux-aarch64/libreallyme_jose_ffi.so", "linux-aarch64.sha256"],
  ["macos-x86_64/libreallyme_jose_ffi.dylib", "macos-x86_64.sha256"],
  ["macos-aarch64/libreallyme_jose_ffi.dylib", "macos-aarch64.sha256"],
  ["windows-x86_64/reallyme_jose_ffi.dll", "windows-x86_64.sha256"],
];

const createTree = (root, digestRoot) => {
  mkdirSync(digestRoot, { recursive: true });
  for (const [suffix, digestFile] of resources) {
    const path = join(root, "me/really/jose/native", suffix);
    const bytes = Buffer.from(`fixture-${suffix}`);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes);
    writeFileSync(
      join(digestRoot, digestFile),
      `${createHash("sha256").update(bytes).digest("hex")}\n`,
    );
  }
};

const verify = (root, digestRoot) => spawnSync(process.execPath, [script, "verify", root, digestRoot], {
  encoding: "utf8",
});

test("accepts the exact five-platform resource tree", () => {
  const root = mkdtempSync(join(tmpdir(), "jose-native-handoff-"));
  try {
    const resourceRoot = join(root, "resources");
    const digestRoot = join(root, "digests");
    createTree(resourceRoot, digestRoot);
    const result = verify(resourceRoot, digestRoot);
    assert.equal(result.status, 0, result.stderr);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("rejects substitution, extra files, and symbolic links", () => {
  for (const mutation of [
    (root) => writeFileSync(join(root, "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so"), "tampered"),
    (root) => writeFileSync(join(root, "unexpected.class"), "unbound"),
    (root) => symlinkSync(join(root, "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so"), join(root, "link.so")),
  ]) {
    const root = mkdtempSync(join(tmpdir(), "jose-native-handoff-negative-"));
    try {
      const resourceRoot = join(root, "resources");
      const digestRoot = join(root, "digests");
      createTree(resourceRoot, digestRoot);
      mutation(resourceRoot);
      assert.notEqual(verify(resourceRoot, digestRoot).status, 0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test("record writes a platform digest as a separate handoff artifact", () => {
  const root = mkdtempSync(join(tmpdir(), "jose-native-record-"));
  try {
    const resourceRoot = join(root, "resources");
    const libraryPath = join(
      resourceRoot,
      "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so",
    );
    const digestRoot = join(root, "recorded-digests");
    mkdirSync(dirname(libraryPath), { recursive: true });
    writeFileSync(libraryPath, "producer bytes");

    const result = spawnSync(
      process.execPath,
      [script, "record", resourceRoot, digestRoot, "linux-x86_64"],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(
      readFileSync(join(digestRoot, "linux-x86_64.sha256"), "ascii"),
      /^[0-9a-f]{64}\n$/u,
    );
  } finally { rmSync(root, { recursive: true, force: true }); }
});
