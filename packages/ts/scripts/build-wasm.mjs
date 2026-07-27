// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_WASM_PACK_VERSION = "0.15.0";
const REQUIRED_WASM_BINDGEN_VERSION = "0.2.126";
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageDirectory = resolve(scriptDirectory, "..");
const repositoryDirectory = resolve(packageDirectory, "..", "..");
const wasmCrateDirectory = resolve(repositoryDirectory, "crates", "wasm");
const outputDirectory = resolve(packageDirectory, "dist", "wasm");

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const requireVersion = (command, requiredVersion) => {
  const result = spawnSync(command, ["--version"], {
    cwd: packageDirectory,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(`${command} ${requiredVersion} is required to build the ReallyMe JOSE WASM artifact.`);
  }
  const match = new RegExp(`^${command} (\\d+\\.\\d+\\.\\d+)$`).exec(result.stdout.trim());
  if (match === null || match[1] !== requiredVersion) {
    fail(`${command} ${requiredVersion} is required; found an unsupported version.`);
  }
};

requireVersion("wasm-pack", REQUIRED_WASM_PACK_VERSION);
requireVersion("wasm-bindgen", REQUIRED_WASM_BINDGEN_VERSION);

const result = spawnSync(
  "wasm-pack",
  [
    "build",
    wasmCrateDirectory,
    "--target",
    "web",
    "--release",
    "--out-dir",
    outputDirectory,
    "--out-name",
    "reallyme_jose_wasm",
    // wasm-pack forwards all arguments after the first Cargo option, so lock
    // enforcement must remain the final argument.
    "--locked",
  ],
  { cwd: packageDirectory, stdio: "inherit" },
);

if (result.status !== 0) process.exit(result.status ?? 1);

// wasm-pack emits standalone package metadata. The reviewed parent package
// owns publication, so only its generated loader and binary are retained.
for (const generatedFile of [
  ".gitignore",
  "package.json",
  "reallyme_jose_wasm.d.ts",
  "reallyme_jose_wasm_bg.wasm.d.ts",
]) {
  rmSync(resolve(outputDirectory, generatedFile), { force: true });
}
