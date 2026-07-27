// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const verifier = fileURLToPath(new URL("./verify_sdk_release_version.mjs", import.meta.url));
const releaseVersion = "0.3.0";

const writeFixture = (root, overrides = new Map()) => {
  const files = new Map([
    ["Cargo.toml", `reallyme-jose-proto = { version = "${releaseVersion}", path = "crates/proto" }\n`],
    ["crates/jose/Cargo.toml", `version = "${releaseVersion}"\n`],
    ["crates/proto/Cargo.toml", `version = "${releaseVersion}"\n`],
    [
      "crates/ffi/Cargo.toml",
      `version = "${releaseVersion}"\nreallyme-jose = { version = "${releaseVersion}", path = "../jose" }\n`,
    ],
    ["crates/wasm/Cargo.toml", `version = "${releaseVersion}"\n`],
    ["packages/kotlin/build.gradle.kts", `version = "${releaseVersion}"\n`],
    ["packages/kotlin-android/build.gradle.kts", `version = "${releaseVersion}"\n`],
    ["Package.swift", `let ffiArtifactVersion = "${releaseVersion}"\n`],
    [
      "packages/ts/package.json",
      `{\n  "version": "${releaseVersion}",\n  "name": "@reallyme/jose"\n}\n`,
    ],
  ]);
  for (const [path, content] of overrides) files.set(path, content);
  for (const [path, content] of files) {
    const absolute = join(root, path);
    mkdirSync(dirname(absolute), { recursive: true });
    writeFileSync(absolute, content, { encoding: "utf8", mode: 0o600 });
  }
};

const runVerifier = (overrides = new Map(), version = releaseVersion) => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-version-test-"));
  try {
    writeFixture(root, overrides);
    return spawnSync(process.execPath, [verifier, version], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

test("accepts one coordinated release version across every public artifact", () => {
  const result = runVerifier();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Rust, Swift, JVM, Android, and TypeScript package versions are bound/u);
});

test("rejects a stale public Rust crate version", () => {
  const result = runVerifier(new Map([["crates/jose/Cargo.toml", 'version = "0.2.1"\n']]));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /crates\/jose\/Cargo\.toml is not bound to 0\.3\.0/u);
});

test("rejects a stale workspace dependency requirement", () => {
  const result = runVerifier(
    new Map([["Cargo.toml", 'reallyme-jose-proto = { version = "0.2.1", path = "crates/proto" }\n']]),
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Cargo\.toml is not bound to 0\.3\.0/u);
});

test("rejects a stale TypeScript package version", () => {
  const result = runVerifier(
    new Map([
      [
        "packages/ts/package.json",
        '{\n  "version": "0.2.5",\n  "name": "@reallyme/jose"\n}\n',
      ],
    ]),
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /packages\/ts\/package\.json is not bound to 0\.3\.0/u);
});

test("rejects a non-semantic release input", () => {
  const result = runVerifier(new Map(), "v0.3.0");
  assert.equal(result.status, 1);
  assert.match(result.stderr, /expected one semantic version without a leading v/u);
});
