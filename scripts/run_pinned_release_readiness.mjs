#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

// The vendored upstream core and repository-specific checker are both pinned
// locally. Release gates must not depend on a live network fetch whose bytes
// are not executed; scheduled CI separately reports upstream drift.
const RELEASE_READINESS_COMMIT = "985cf16f866bcdbd384edd8a9b6f332b38c5eb52";
const RELEASE_READINESS_CORE_SHA256 =
  "6bf50e9e5e55805191217c39e4291067d227a197ea46ab3d371d308f3f878a20";
const LOCAL_CHECKER_SHA256 =
  "d09cbda25d0f81126a6b111b27effd3777a9428cd56a83b32ac875cff5d82dfb";
const VENDORED_CORE_PATH = "scripts/release-readiness/core.mjs";
const LOCAL_CHECKER_PATH = "scripts/check_release_readiness.mjs";
const MAX_CORE_BYTES = 262_144;
const MAX_CHECKER_BYTES = 524_288;

const fail = (message) => {
  console.error(`pinned release readiness failed: ${message}`);
  process.exit(1);
};

const sha256 = (value) => createHash("sha256").update(value).digest();

const expectedDigest = Buffer.from(RELEASE_READINESS_CORE_SHA256, "hex");
if (expectedDigest.length !== 32) {
  fail("configured core digest is invalid");
}
const expectedCheckerDigest = Buffer.from(LOCAL_CHECKER_SHA256, "hex");
if (expectedCheckerDigest.length !== 32) {
  fail("configured local checker digest is invalid");
}

let localCore;
let localChecker;
try {
  const checkerStatus = lstatSync(LOCAL_CHECKER_PATH);
  if (checkerStatus.isSymbolicLink() || !checkerStatus.isFile()) {
    fail("local checker must be a regular file");
  }
  if (checkerStatus.size === 0 || checkerStatus.size > MAX_CHECKER_BYTES) {
    fail("local checker size is outside the accepted boundary");
  }
  const status = lstatSync(VENDORED_CORE_PATH);
  if (status.isSymbolicLink() || !status.isFile()) {
    fail("vendored core must be a regular file");
  }
  if (status.size === 0 || status.size > MAX_CORE_BYTES) {
    fail("vendored core size is outside the accepted boundary");
  }
  localChecker = readFileSync(LOCAL_CHECKER_PATH);
  localCore = readFileSync(VENDORED_CORE_PATH);
} catch {
  fail("release readiness inputs are missing or inaccessible");
}
if (!timingSafeEqual(sha256(localChecker), expectedCheckerDigest)) {
  fail("local checker does not match the reviewed repository policy pin");
}
if (!timingSafeEqual(sha256(localCore), expectedDigest)) {
  fail("vendored core does not match the reviewed upstream pin");
}

const checker = spawnSync(process.execPath, [LOCAL_CHECKER_PATH, ...process.argv.slice(2)], {
  env: process.env,
  stdio: "inherit",
});
if (checker.error !== undefined) {
  fail("local release readiness checker could not be started");
}
if (!Number.isInteger(checker.status)) {
  fail("local release readiness checker ended without a deterministic status");
}
process.exit(checker.status);
