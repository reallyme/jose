#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const checksumPattern = /^[0-9a-f]{64}$/u;
const versionPattern = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const maximumArchiveBytes = 536_870_912;

const fail = (reason) => {
  console.error(`Swift release artifact verification failed: ${reason}`);
  process.exit(1);
};

const [, , archivePath, sidecarPath, manifestPath, expectedVersion, mode] = process.argv;
if (
  archivePath === undefined ||
  sidecarPath === undefined ||
  manifestPath === undefined ||
  expectedVersion === undefined ||
  !versionPattern.test(expectedVersion) ||
  mode !== undefined
) {
  fail("expected archive, checksum sidecar, Package.swift, and semantic version");
}

const readRegular = (path, maximumBytes, label) => {
  let status;
  try { status = lstatSync(path); } catch { fail(`${label} is inaccessible`); }
  if (status.isSymbolicLink() || !status.isFile() || status.size < 1 || status.size > maximumBytes) {
    fail(`${label} is not a bounded regular file`);
  }
  return readFileSync(path);
};

const sidecarBytes = readRegular(sidecarPath, 128, "checksum sidecar");
const sidecarText = sidecarBytes.toString("utf8");
const sidecar = sidecarText.endsWith("\n") ? sidecarText.slice(0, -1) : "";
if (!checksumPattern.test(sidecar) || sidecarText !== `${sidecar}\n`) {
  fail("checksum sidecar is malformed");
}
readRegular(archivePath, maximumArchiveBytes, "XCFramework archive");
const manifest = readRegular(manifestPath, 1_048_576, "Package.swift").toString("utf8");

let computed;
try {
  computed = execFileSync("swift", ["package", "compute-checksum", archivePath], {
    encoding: "utf8",
    maxBuffer: 1024,
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
} catch {
  fail("SwiftPM could not compute the archive checksum");
}
if (computed !== sidecar) fail("archive and sidecar checksums differ");

const stringAssignment = (name, pattern) => {
  const expression = new RegExp(`^let ${name} = "(${pattern})"$`, "gmu");
  const matches = [...manifest.matchAll(expression)];
  if (matches.length !== 1) fail(`Package.swift must define exactly one ${name}`);
  return matches[0][1];
};
const manifestChecksum = stringAssignment("ffiArtifactChecksum", "[0-9a-f]{64}");
if (manifestChecksum !== computed) {
  fail("Package.swift checksum is not bound to the verified archive");
}
if (stringAssignment("ffiArtifactVersion", "(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)") !== expectedVersion) {
  fail("Package.swift version differs from the release version");
}
if (stringAssignment("ffiArtifactLocalPathOverride", "") !== "") {
  fail("release manifest contains a local artifact override");
}

let entries;
try {
  entries = execFileSync("unzip", ["-Z1", archivePath], {
    encoding: "utf8",
    maxBuffer: 1_048_576,
    stdio: ["ignore", "pipe", "ignore"],
  });
} catch {
  fail("XCFramework archive cannot be listed");
}
for (const required of [
  "ReallyMeJOSEFFI.xcframework/Info.plist",
  "macos-arm64_x86_64/Headers/reallyme_jose.h",
  "ios-arm64/Headers/reallyme_jose.h",
  "ios-arm64_x86_64-simulator/Headers/reallyme_jose.h",
  "macos-arm64_x86_64/Modules/module.modulemap",
  "ios-arm64/Modules/module.modulemap",
  "ios-arm64_x86_64-simulator/Modules/module.modulemap",
]) {
  if (!entries.includes(required)) fail(`XCFramework is missing ${required}`);
}
if (!manifest.includes("ReallyMeJOSEFFI.xcframework.zip") || !manifest.includes("checksum: ffiArtifactChecksum")) {
  fail("Package.swift binary target is not version/checksum bound");
}

const libraries = [
  "ReallyMeJOSEFFI.xcframework/macos-arm64_x86_64/libreallyme_jose_ffi_macos.a",
  "ReallyMeJOSEFFI.xcframework/ios-arm64/libreallyme_jose_ffi_ios.a",
  "ReallyMeJOSEFFI.xcframework/ios-arm64_x86_64-simulator/libreallyme_jose_ffi_ios_simulator.a",
];
let llvmNm;
try {
  const rustTargetLibrary = execFileSync("rustc", ["--print", "target-libdir"], {
    encoding: "utf8",
    maxBuffer: 4096,
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
  llvmNm = resolve(rustTargetLibrary, "..", "bin", "llvm-nm");
  readRegular(llvmNm, 134_217_728, "Rust LLVM symbol inspector");
} catch {
  fail("the Rust toolchain LLVM symbol inspector is unavailable");
}
const requiredSymbols = [
  "rm_jose_abi_version",
  "rm_jose_execute_operation_v1",
  "rm_jose_execute_operation_json_v1",
  "rm_jose_zeroize_buffer",
];
const temporaryDirectory = mkdtempSync(join(tmpdir(), "reallyme-jose-swift-"));
try {
  for (const [index, library] of libraries.entries()) {
    if (!entries.includes(library)) fail(`XCFramework is missing ${library}`);
    const bytes = execFileSync("unzip", ["-p", archivePath, library], {
      encoding: null,
      maxBuffer: maximumArchiveBytes,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const path = join(temporaryDirectory, `slice-${index}.a`);
    writeFileSync(path, bytes, { mode: 0o600 });
    const symbols = execFileSync(llvmNm, ["-g", path], {
      encoding: "utf8",
      maxBuffer: 16_777_216,
      stdio: ["ignore", "pipe", "ignore"],
    });
    for (const symbol of requiredSymbols) {
      if (!new RegExp(`(?:^|\\s)_?${symbol}$`, "mu").test(symbols)) {
        fail(`${library} is missing required C ABI symbols`);
      }
    }
  }
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}

console.log("Swift XCFramework layout, checksum, version, and package binding verified");
