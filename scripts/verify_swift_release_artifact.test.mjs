#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./verify_swift_release_artifact.mjs", import.meta.url));
const requiredSymbols = [
  "rm_jose_abi_version",
  "rm_jose_execute_operation_v1",
  "rm_jose_execute_operation_json_v1",
  "rm_jose_zeroize_buffer",
];

const writeExecutable = (path, source) => {
  writeFileSync(path, source, { mode: 0o700 });
  chmodSync(path, 0o700);
};

const writeFixture = (root, { bound = true, forgedSidecar = false, omitSymbol = false } = {}) => {
  const payload = join(root, "payload");
  const framework = join(payload, "ReallyMeJOSEFFI.xcframework");
  const slices = [
    ["macos-arm64_x86_64", "libreallyme_jose_ffi_macos.a"],
    ["ios-arm64", "libreallyme_jose_ffi_ios.a"],
    ["ios-arm64_x86_64-simulator", "libreallyme_jose_ffi_ios_simulator.a"],
  ];
  mkdirSync(framework, { recursive: true });
  writeFileSync(join(framework, "Info.plist"), "fixture\n");
  for (const [slice, library] of slices) {
    const headers = join(framework, slice, "Headers");
    const modules = join(framework, slice, "Modules");
    mkdirSync(headers, { recursive: true });
    mkdirSync(modules, { recursive: true });
    writeFileSync(join(headers, "reallyme_jose.h"), "/* fixture */\n");
    writeFileSync(join(modules, "module.modulemap"), "module Fixture {}\n");
    writeFileSync(join(framework, slice, library), `fixture ${slice}\n`);
  }

  const archive = join(root, "ReallyMeJOSEFFI.xcframework.zip");
  execFileSync("zip", ["-X", "-q", "-r", archive, "ReallyMeJOSEFFI.xcframework"], {
    cwd: payload,
    stdio: "pipe",
  });
  const checksum = createHash("sha256").update(readFileSync(archive)).digest("hex");
  const sidecar = join(root, "ReallyMeJOSEFFI.xcframework.checksum");
  writeFileSync(sidecar, `${forgedSidecar ? "0".repeat(64) : checksum}\n`);

  const manifest = join(root, "Package.swift");
  writeFileSync(
    manifest,
    `let ffiArtifactChecksum = "${checksum}"
let ffiArtifactVersion = "0.3.0"
let ffiArtifactLocalPathOverride = ""
.binaryTarget(
  name: "ReallyMeJOSEFFI",
  url: "https://github.com/reallyme/jose/releases/download/v\\(ffiArtifactVersion)/ReallyMeJOSEFFI.xcframework.zip",
  checksum: ${bound ? "ffiArtifactChecksum" : `"${checksum}"`}
)
`,
  );

  const tools = join(root, "tools");
  const rustTargetLibrary = join(root, "rust-toolchain", "lib", "rustlib", "fixture", "lib");
  const llvmBin = join(root, "rust-toolchain", "lib", "rustlib", "fixture", "bin");
  mkdirSync(tools, { recursive: true });
  mkdirSync(rustTargetLibrary, { recursive: true });
  mkdirSync(llvmBin, { recursive: true });
  writeExecutable(
    join(tools, "swift"),
    "#!/bin/sh\nset -eu\n[ \"$1\" = package ]\n[ \"$2\" = compute-checksum ]\nshasum -a 256 \"$3\" | cut -d ' ' -f 1\n",
  );
  writeExecutable(join(tools, "rustc"), `#!/bin/sh\nprintf '%s\\n' '${rustTargetLibrary}'\n`);
  const symbols = omitSymbol ? requiredSymbols.slice(1) : requiredSymbols;
  writeExecutable(
    join(llvmBin, "llvm-nm"),
    `#!/bin/sh\nprintf '%s\\n' ${symbols.map((symbol) => `'_${symbol}'`).join(" ")}\n`,
  );
  return {
    archive,
    env: { ...process.env, PATH: `${tools}${delimiter}${process.env.PATH ?? ""}` },
    manifest,
    sidecar,
  };
};

const runVerifier = (fixture) =>
  execFileSync(
    process.execPath,
    [script, fixture.archive, fixture.sidecar, fixture.manifest, "0.3.0"],
    { env: fixture.env, stdio: "pipe" },
  );

test("accepts a checksum-bound archive with every required slice and ABI symbol", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-swift-release-"));
  try {
    assert.doesNotThrow(() => runVerifier(writeFixture(root)));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("recomputes the archive bytes and rejects a forged checksum sidecar", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-swift-release-"));
  try {
    assert.throws(() => runVerifier(writeFixture(root, { forgedSidecar: true })));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects a manifest that does not consume its checksum binding", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-swift-release-"));
  try {
    assert.throws(() => runVerifier(writeFixture(root, { bound: false })));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects an archive whose native slices omit a required ABI symbol", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-jose-swift-release-"));
  try {
    assert.throws(() => runVerifier(writeFixture(root, { omitSymbol: true })));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
