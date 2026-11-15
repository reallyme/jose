#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { generateContractValues } from "./generate-contract-values.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
export function requireGeneratorVersions(run = spawnSync) {
  for (const name of ["protoc-gen-reallyme-buffa", "protoc-gen-reallyme-buffa-packaging"]) {
    const result = run(name, ["--version"], { encoding: "utf8", cwd: root });
    if (result.status !== 0 || result.error !== undefined || result.stdout.trim() !== `${name} 0.1.2`) {
      throw new TypeError("the published ReallyMe Buffa 0.1.2 generators are required");
    }
  }
}

export function generateJoseProto() {
  requireGeneratorVersions();
  for (const [command, args] of [
    ["buf", ["lint"]],
    ["buf", ["generate"]],
  ]) {
    const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
    if (result.status !== 0 || result.error !== undefined) throw new TypeError("protobuf generation failed");
  }
  // These files are schema-derived API bindings, not modifications to Buffa's
  // output. Rust cleanup and JSON behavior come entirely from native options.
  generateContractValues();
  for (const [command, args] of [
    [process.execPath, ["scripts/harden-generated-jose-jvm.mjs"]],
    [process.execPath, ["scripts/harden-generated-jose-swift.mjs"]],
    ["cargo", ["fmt", "--package", "reallyme-jose-proto"]],
  ]) {
    const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
    if (result.status !== 0 || result.error !== undefined) throw new TypeError("SDK generation or formatting failed");
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new TypeError("unsupported generation argument");
  generateJoseProto();
}
