#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { lstatSync, readFileSync } from "node:fs";

const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const [, , expectedVersion] = process.argv;
const fail = (reason) => {
  console.error(`SDK release version verification failed: ${reason}`);
  process.exit(1);
};
if (expectedVersion === undefined || !VERSION_PATTERN.test(expectedVersion)) {
  fail("expected one semantic version without a leading v");
}

const readRegular = (path) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    fail(`${path} is inaccessible`);
  }
  if (status.isSymbolicLink() || !status.isFile() || status.size < 1 || status.size > 1_048_576) {
    fail(`${path} is not a bounded regular file`);
  }
  return readFileSync(path, "utf8");
};

const assignments = [
  ["crates/jose/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["crates/proto/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["crates/ffi/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["crates/wasm/Cargo.toml", /^version = "([^"]+)"$/gmu],
  ["Cargo.toml", /^reallyme-jose-proto = \{ version = "([^"]+)"/gmu],
  ["crates/ffi/Cargo.toml", /^reallyme-jose = \{ version = "([^"]+)"/gmu],
  ["packages/kotlin/build.gradle.kts", /^version = "([^"]+)"$/gmu],
  ["packages/kotlin-android/build.gradle.kts", /^version = "([^"]+)"$/gmu],
  ["Package.swift", /^let ffiArtifactVersion = "([^"]+)"$/gmu],
  ["packages/ts/package.json", /^  "version": "([^"]+)",$/gmu],
];
for (const [path, pattern] of assignments) {
  const matches = [...readRegular(path).matchAll(pattern)];
  if (matches.length !== 1 || matches[0][1] !== expectedVersion) {
    fail(`${path} is not bound to ${expectedVersion}`);
  }
}
console.log(`Rust, Swift, JVM, Android, and TypeScript package versions are bound to ${expectedVersion}`);
