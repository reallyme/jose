// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { prepareSemverBaseline, SemverBaselineError } from "./prepare_semver_baseline.mjs";

const releases = Object.freeze({
  "reallyme-codec": Object.freeze({
    version: "0.1.20",
    checksum: "c325178f3265f5473b077e65f8dbc28f0b837066668ede3fabbdc27bbac28244",
  }),
  "reallyme-codec-base64": Object.freeze({
    version: "0.1.20",
    checksum: "82c020399aa75b68bfd3e800cc4888ee422ceb39134be79297c785763120d116",
  }),
  "reallyme-crypto": Object.freeze({
    version: "0.1.6",
    checksum: "ed3fd5abf6acbc465ed1dea322b4e984935b6ea5179882c1516d4df471845765",
  }),
  "reallyme-crypto-core": Object.freeze({
    version: "0.1.2",
    checksum: "3d5ef8109af8ad6268bd322c4f3adb15f6d05b209907ebf1b49fc2b11e7dd576",
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
  writeFileSync(
    join(root, "crates/Cargo.toml"),
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
  assert.match(manifest, /reallyme-codec = \{ version = "=0[.]1[.]20"/u);
  assert.match(manifest, /reallyme-crypto = \{ version = "=0[.]1[.]6"/u);
  const crateManifest = readFileSync(join(root, "crates/Cargo.toml"), "utf8");
  assert.match(
    crateManifest,
    /semver-baseline-codec-base64 = \{ package = "reallyme-codec-base64", version = "=0[.]1[.]20" \}/u,
  );
  assert.match(
    crateManifest,
    /semver-baseline-crypto-core = \{ package = "reallyme-crypto-core", version = "=0[.]1[.]2" \}/u,
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
    readFileSync(manifestPath, "utf8").replace('version = "0.1.20"', 'version = "0.1.21"'),
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
