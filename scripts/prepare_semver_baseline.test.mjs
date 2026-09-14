// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { prepareSemverBaseline, SemverBaselineError } from "./prepare_semver_baseline.mjs";

const releases = Object.freeze({
  "reallyme-codec": Object.freeze({
    version: "0.2.1",
    checksum: "022909fcbf0d6cbd873b83cc6332934bc0d2566e7b611eb60e8d35eae8fbc9b3",
  }),
  "reallyme-codec-base64": Object.freeze({
    version: "0.2.1",
    checksum: "cba709377618821186e51751683e7e455ba85045303f81485f50826e2c4dcc8a",
  }),
  "reallyme-crypto": Object.freeze({
    version: "0.3.4",
    checksum: "6d9d1201e1a02e0be139b8a9c7b1d4c4bc2efbe1dd18f38bd207d0fbdac2628b",
  }),
  "reallyme-crypto-core": Object.freeze({
    version: "0.3.4",
    checksum: "6cf1bb671a7b2549d0189a9213d2bdaed24bf13772070288102f3f37e27e9049",
  }),
});

const fixture = () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-semver-baseline-"));
  const manifest = Object.entries(releases)
    .map(([packageName, release]) =>
      `${packageName} = { version = "${release.version}", default-features = false }`,
    )
    .join("\n");
  writeFileSync(join(root, "Cargo.toml"), `${manifest}\n`, "utf8");
  const lockfile = Object.entries(releases)
    .map(
      ([packageName, release]) =>
        `[[package]]\nname = "${packageName}"\nversion = "${release.version}"\n` +
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n' +
        `checksum = "${release.checksum}"\n`,
    )
    .join("\n");
  writeFileSync(join(root, "Cargo.lock"), lockfile, "utf8");
  mkdirSync(join(root, "crates"));
  mkdirSync(join(root, "crates/jose"));
  writeFileSync(
    join(root, "crates/jose/Cargo.toml"),
    `[dependencies]\n\n[target.'cfg(target_arch = "wasm32")'.dependencies]\n`,
    "utf8",
  );
  return Object.freeze({
    root,
    lockfileSha256: createHash("sha256").update(lockfile).digest("hex"),
  });
};

test("freezes reviewed baseline dependencies to their lockfile versions", () => {
  const { root, lockfileSha256 } = fixture();
  prepareSemverBaseline(root, lockfileSha256);
  const manifest = readFileSync(join(root, "Cargo.toml"), "utf8");
  assert.match(manifest, /reallyme-codec = \{ version = "=0[.]2[.]1"/u);
  assert.match(manifest, /reallyme-crypto = \{ version = "=0[.]3[.]4"/u);
  const crateManifest = readFileSync(join(root, "crates/jose/Cargo.toml"), "utf8");
  assert.match(
    crateManifest,
    /semver-baseline-codec-base64 = \{ package = "reallyme-codec-base64", version = "=0[.]2[.]1" \}/u,
  );
  assert.match(
    crateManifest,
    /semver-baseline-crypto-core = \{ package = "reallyme-crypto-core", version = "=0[.]3[.]4" \}/u,
  );
});

test("rejects a changed registry checksum", () => {
  const { root, lockfileSha256 } = fixture();
  const lockPath = join(root, "Cargo.lock");
  writeFileSync(
    lockPath,
    readFileSync(lockPath, "utf8").replace(/checksum = "[^"]+"/u, 'checksum = "changed"'),
  );
  assert.throws(
    () => prepareSemverBaseline(root, lockfileSha256),
    (error) => error instanceof SemverBaselineError && error.code === "INVALID_LOCKFILE",
  );
});

test("rejects dependency drift and repeated preparation", () => {
  const { root, lockfileSha256 } = fixture();
  const manifestPath = join(root, "Cargo.toml");
  writeFileSync(
    manifestPath,
    readFileSync(manifestPath, "utf8").replace('version = "0.2.1"', 'version = "0.2.2"'),
  );
  assert.throws(
    () => prepareSemverBaseline(root, lockfileSha256),
    (error) => error instanceof SemverBaselineError && error.code === "INVALID_DEPENDENCY",
  );

  const cleanFixture = fixture();
  prepareSemverBaseline(cleanFixture.root, cleanFixture.lockfileSha256);
  assert.throws(
    () => prepareSemverBaseline(cleanFixture.root, cleanFixture.lockfileSha256),
    (error) => error instanceof SemverBaselineError && error.code === "INVALID_DEPENDENCY",
  );
});
