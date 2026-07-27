#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RUST_SEMVER_BASELINE_COMMIT = "66d54835235c414051009523670afb6bb3e51007";

const MAX_MANIFEST_BYTES = 65_536;
const MAX_LOCKFILE_BYTES = 524_288;
const BASELINE_LOCKFILE_SHA256 =
  "60cdf733148731461d0f13503a4b2c839eeaa9131c74e8004fb12fe7add5741c";
const CRATE_DEPENDENCY_MARKER = "\n[target.'cfg(target_arch = \"wasm32\")'.dependencies]\n";

// Freeze direct ReallyMe dependencies at the versions reviewed with the 0.2.0
// release. Without exact requirements, Cargo may resolve newer 0.x releases
// while rustdoc is constructing the historical API baseline.
const BASELINE_DEPENDENCIES = Object.freeze([
  Object.freeze({
    packageName: "reallyme-codec",
    version: "0.1.20",
  }),
  Object.freeze({
    packageName: "reallyme-crypto",
    version: "0.1.6",
  }),
]);

const ERROR_MESSAGES = Object.freeze({
  INVALID_ARGUMENT: "the semver baseline path is invalid",
  INVALID_CHECKOUT: "the semver baseline checkout does not match the reviewed commit",
  INVALID_FILE: "a semver baseline file is missing, unsafe, or outside its size boundary",
  INVALID_DEPENDENCY: "the semver baseline dependency policy does not match the reviewed release",
  INVALID_LOCKFILE: "the semver baseline lockfile provenance does not match the reviewed release",
  WRITE_FAILED: "the semver baseline dependency freeze could not be written",
});

export class SemverBaselineError extends Error {
  constructor(code) {
    const acceptedCode = Object.hasOwn(ERROR_MESSAGES, code) ? code : "INVALID_FILE";
    super(ERROR_MESSAGES[acceptedCode]);
    this.name = "SemverBaselineError";
    this.code = acceptedCode;
  }
}

const fail = (code) => {
  throw new SemverBaselineError(code);
};

const readRegularFile = (path, maximumBytes) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    fail("INVALID_FILE");
  }
  if (status.isSymbolicLink() || !status.isFile() || status.size === 0 || status.size > maximumBytes) {
    fail("INVALID_FILE");
  }
  try {
    return readFileSync(path, "utf8");
  } catch {
    fail("INVALID_FILE");
  }
};

const sha256 = (value) => createHash("sha256").update(value).digest();

const parseReallyMeReleases = (lockfile) => {
  const releases = new Map();
  for (const block of lockfile.split("[[package]]")) {
    const name = block.match(/^name = "([^"]+)"$/mu)?.[1];
    if (name === undefined || !/^reallyme-(?:codec|crypto)(?:-|$)/u.test(name)) {
      continue;
    }
    const version = block.match(/^version = "([0-9]+[.][0-9]+[.][0-9]+)"$/mu)?.[1];
    const source = block.match(/^source = "([^"]+)"$/mu)?.[1];
    const checksum = block.match(/^checksum = "([0-9a-f]{64})"$/mu)?.[1];
    if (
      version === undefined ||
      source !== "registry+https://github.com/rust-lang/crates.io-index" ||
      checksum === undefined ||
      releases.has(name)
    ) {
      fail("INVALID_LOCKFILE");
    }
    releases.set(name, version);
  }
  for (const dependency of BASELINE_DEPENDENCIES) {
    if (releases.get(dependency.packageName) !== dependency.version) {
      fail("INVALID_LOCKFILE");
    }
  }
  return releases;
};

const readBaselineReleases = (root, expectedLockfileSha256) => {
  const lockfile = readRegularFile(resolve(root, "Cargo.lock"), MAX_LOCKFILE_BYTES);
  const expectedDigest = Buffer.from(expectedLockfileSha256, "hex");
  if (expectedDigest.length !== 32 || !timingSafeEqual(sha256(lockfile), expectedDigest)) {
    fail("INVALID_LOCKFILE");
  }
  return parseReallyMeReleases(lockfile);
};

export const prepareSemverBaseline = (
  root,
  expectedLockfileSha256 = BASELINE_LOCKFILE_SHA256,
) => {
  const releases = readBaselineReleases(root, expectedLockfileSha256);
  const manifestPath = resolve(root, "Cargo.toml");
  let manifest = readRegularFile(manifestPath, MAX_MANIFEST_BYTES);
  for (const dependency of BASELINE_DEPENDENCIES) {
    const oldNeedle = `${dependency.packageName} = { version = "${dependency.version}"`;
    const frozenNeedle = `${dependency.packageName} = { version = "=${dependency.version}"`;
    if (manifest.split(oldNeedle).length !== 2 || manifest.includes(frozenNeedle)) {
      fail("INVALID_DEPENDENCY");
    }
    manifest = manifest.replace(oldNeedle, frozenNeedle);
  }
  const crateManifestPath = resolve(root, "crates/Cargo.toml");
  let crateManifest = readRegularFile(crateManifestPath, MAX_MANIFEST_BYTES);
  if (crateManifest.split(CRATE_DEPENDENCY_MARKER).length !== 2) {
    fail("INVALID_DEPENDENCY");
  }
  const directDependencies = new Set(
    BASELINE_DEPENDENCIES.map((dependency) => dependency.packageName),
  );
  const frozenTransitiveDependencies = [...releases]
    .filter(([packageName]) => !directDependencies.has(packageName))
    .map(
      ([packageName, version]) =>
        `semver-baseline-${packageName.slice("reallyme-".length)} = { package = "${packageName}", version = "=${version}" }`,
    )
    .join("\n");
  if (frozenTransitiveDependencies.length === 0 || crateManifest.includes("semver-baseline-")) {
    fail("INVALID_DEPENDENCY");
  }
  crateManifest = crateManifest.replace(
    CRATE_DEPENDENCY_MARKER,
    `\n# These exact constraints preserve the dependency graph of the reviewed release.\n${frozenTransitiveDependencies}\n${CRATE_DEPENDENCY_MARKER}`,
  );
  try {
    writeFileSync(manifestPath, manifest, { encoding: "utf8", flag: "w" });
    writeFileSync(crateManifestPath, crateManifest, { encoding: "utf8", flag: "w" });
  } catch {
    fail("WRITE_FAILED");
  }
};

const validateCheckout = (root) => {
  const result = spawnSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
    stdio: "pipe",
  });
  if (
    result.error !== undefined ||
    result.status !== 0 ||
    result.stdout.trim() !== RUST_SEMVER_BASELINE_COMMIT
  ) {
    fail("INVALID_CHECKOUT");
  }
};

const isMain =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    if (process.argv.length !== 3) {
      fail("INVALID_ARGUMENT");
    }
    const baselineRoot = realpathSync(resolve(process.argv[2]));
    validateCheckout(baselineRoot);
    prepareSemverBaseline(baselineRoot);
    console.log(`prepared Rust semver baseline at ${RUST_SEMVER_BASELINE_COMMIT}`);
  } catch (error) {
    if (error instanceof SemverBaselineError) {
      console.error(`semver baseline preparation failed [${error.code}]: ${error.message}`);
    } else {
      console.error("semver baseline preparation failed [INVALID_ARGUMENT]: invalid baseline input");
    }
    process.exitCode = 1;
  }
}
