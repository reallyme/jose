#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { createReadStream, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_LIBRARY_BYTES = 536_870_912;
const MAX_ENTRIES = 64;
const RESOURCE_ROOT = "me/really/jose/native";
const PLATFORMS = Object.freeze([
  ["linux-x86_64", "libreallyme_jose_ffi.so"],
  ["linux-aarch64", "libreallyme_jose_ffi.so"],
  ["macos-x86_64", "libreallyme_jose_ffi.dylib"],
  ["macos-aarch64", "libreallyme_jose_ffi.dylib"],
  ["windows-x86_64", "reallyme_jose_ffi.dll"],
].map(([id, library]) => Object.freeze({
  id,
  relativePath: `${RESOURCE_ROOT}/${id}/${library}`,
  digestFile: `${id}.sha256`,
})));

const fail = (reason) => {
  console.error(`native artifact handoff verification failed: ${reason}`);
  process.exit(1);
};

const requireDirectory = (path) => {
  let status;
  try { status = lstatSync(path); } catch { fail("native resource root is inaccessible"); }
  if (status.isSymbolicLink() || !status.isDirectory()) {
    fail("native resource root is not a regular directory");
  }
};

const collectFiles = (root) => {
  const files = [];
  let entriesSeen = 0;
  const walk = (directory, depth) => {
    if (depth > 5) fail("native resource tree exceeds the supported depth");
    let entries;
    try { entries = readdirSync(directory, { withFileTypes: true }); }
    catch { fail("native resource tree is unreadable"); }
    for (const entry of entries) {
      entriesSeen += 1;
      if (entriesSeen > MAX_ENTRIES) fail("native resource tree contains too many entries");
      const path = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) fail("native resource tree contains a symbolic link");
      if (entry.isDirectory()) walk(path, depth + 1);
      else if (entry.isFile()) files.push(relative(root, path).split(sep).join("/"));
      else fail("native resource tree contains an unsupported entry");
    }
  };
  walk(root, 0);
  return files.sort();
};

const digestFile = async (path) => {
  let before;
  try { before = lstatSync(path); } catch { fail("native library is inaccessible"); }
  if (before.isSymbolicLink() || !before.isFile() || before.size < 1 || before.size > MAX_LIBRARY_BYTES) {
    fail("native library is not a bounded regular file");
  }
  const hash = createHash("sha256");
  try {
    await new Promise((resolveStream, rejectStream) => {
      const stream = createReadStream(path);
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("error", rejectStream);
      stream.on("end", resolveStream);
    });
  } catch { fail("native library could not be read"); }
  let after;
  try { after = lstatSync(path); } catch { fail("native library changed while it was hashed"); }
  if (
    after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
    after.mtimeMs !== before.mtimeMs
  ) {
    fail("native library changed while it was hashed");
  }
  return hash.digest("hex");
};

const requireExactFiles = (actual, expected) => {
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((path, index) => path !== sortedExpected[index])) {
    fail("native artifact does not contain the exact expected file set");
  }
};

const [, , operation, rootArgument, digestRootArgument, platformArgument] = process.argv;
if (
  (operation !== "record" && operation !== "verify") ||
  rootArgument === undefined ||
  digestRootArgument === undefined
) {
  fail("usage: verify_native_artifact_handoff.mjs <record|verify> <root> <digest-root> [platform]");
}
const root = resolve(rootArgument);
const digestRoot = resolve(digestRootArgument);
requireDirectory(root);
const actualFiles = collectFiles(root);

if (operation === "record") {
  const platform = PLATFORMS.find((candidate) => candidate.id === platformArgument);
  if (platform === undefined) fail("record requires a supported platform");
  requireExactFiles(actualFiles, [platform.relativePath]);
  try {
    mkdirSync(digestRoot, { recursive: true, mode: 0o700 });
    writeFileSync(
      resolve(digestRoot, platform.digestFile),
      `${await digestFile(resolve(root, platform.relativePath))}\n`,
      { encoding: "ascii", mode: 0o600 },
    );
  } catch { fail("producer digest could not be written"); }
} else {
  requireExactFiles(actualFiles, PLATFORMS.map((platform) => platform.relativePath));
  requireDirectory(digestRoot);
  requireExactFiles(collectFiles(digestRoot), PLATFORMS.map((platform) => platform.digestFile));
  for (const platform of PLATFORMS) {
    let expected;
    try {
      expected = readFileSync(resolve(digestRoot, platform.digestFile), "ascii").trim();
    } catch {
      fail(`producer digest for ${platform.id} is inaccessible`);
    }
    if (!CHECKSUM_PATTERN.test(expected)) {
      fail(`producer digest for ${platform.id} is missing or malformed`);
    }
    if (await digestFile(resolve(root, platform.relativePath)) !== expected) {
      fail(`downloaded library for ${platform.id} differs from its producer output`);
    }
  }
}
console.log("native artifact handoff verified");
