#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readUtf8 = (path) => readFileSync(path, "utf8");
const requiredFiles = [
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/dist/proto.js",
  "package/dist/proto.d.ts",
  "package/dist/wasm/reallyme_jose_wasm.js",
  "package/dist/wasm/reallyme_jose_wasm_bg.wasm",
  "package/dist/wasmModuleTypes.d.ts",
  "package/LICENSE",
  "package/NOTICE",
  "package/README.md",
  "package/package.json",
];

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const packageJson = JSON.parse(readUtf8(resolve(packageDirectory, "package.json")));
const packageExports = packageJson.exports;
if (
  typeof packageExports !== "object" ||
  packageExports === null ||
  packageExports["./wasm/reallyme_jose_wasm.js"]?.default !==
    "./dist/wasm/reallyme_jose_wasm.js" ||
  packageExports["./wasm/reallyme_jose_wasm.js"]?.types !==
    "./dist/wasmModuleTypes.d.ts" ||
  packageExports["./wasm/reallyme_jose_wasm_bg.wasm"]?.default !==
    "./dist/wasm/reallyme_jose_wasm_bg.wasm"
) {
  fail("package.json does not expose the reviewed raw WASM artifact contract.");
}

const npmCacheDirectory = mkdtempSync(join(tmpdir(), "reallyme-jose-npm-pack-"));
let result;
try {
  result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: packageDirectory,
    encoding: "utf8",
    env: { ...process.env, npm_config_cache: npmCacheDirectory },
  });
} finally {
  rmSync(npmCacheDirectory, { force: true, recursive: true });
}
if (result.status !== 0) {
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}

let entries;
try {
  entries = JSON.parse(result.stdout);
} catch {
  fail("npm pack --dry-run --json returned invalid JSON.");
}
if (!Array.isArray(entries) || entries.length !== 1 || !Array.isArray(entries[0]?.files)) {
  fail("npm pack --dry-run --json returned an unexpected package manifest.");
}
const names = new Set(
  entries[0].files
    .filter((file) => typeof file?.path === "string")
    .map((file) => `package/${file.path}`),
);
const missingFiles = requiredFiles.filter((file) => !names.has(file));
if (missingFiles.length !== 0) {
  fail(`npm package is missing required release artifacts:\n- ${missingFiles.join("\n- ")}`);
}

const declarations = readUtf8(resolve(packageDirectory, "dist", "wasmModuleTypes.d.ts"));
const expectedFunctions = new Set(["executeOperation", "executeOperationJson"]);
for (const expected of expectedFunctions) {
  if (!declarations.includes(`export declare function ${expected}(`)) {
    fail(`raw WASM declaration is missing ${expected}.`);
  }
}
if (/processProto|Derand|deterministic/i.test(declarations)) {
  fail("raw WASM declarations expose a removed alias or conformance-only operation.");
}

const wasmGlue = readUtf8(resolve(packageDirectory, "dist", "wasm", "reallyme_jose_wasm.js"));
const wasmBinary = readFileSync(
  resolve(packageDirectory, "dist", "wasm", "reallyme_jose_wasm_bg.wasm"),
);
let wasmModule;
try {
  wasmModule = new WebAssembly.Module(wasmBinary);
} catch {
  fail("published WASM artifact is not a valid WebAssembly module.");
}

const semanticExports = new Set(
  WebAssembly.Module.exports(wasmModule)
    .filter((item) => item.kind === "function" && !item.name.startsWith("__"))
    .map((item) => item.name),
);
if (
  semanticExports.size !== expectedFunctions.size ||
  [...expectedFunctions].some((name) => !semanticExports.has(name))
) {
  fail(`published WASM has an unreviewed semantic export: ${[...semanticExports].sort().join(", ")}`);
}
for (const name of expectedFunctions) {
  if (!wasmGlue.includes(`export function ${name}`)) {
    fail(`generated WASM glue is missing ${name}.`);
  }
}

// Any new import must be reviewed because imports can silently delegate crypto
// operations to mutable ambient JavaScript state.
const allowedImportNames = [
  /^__wbg_new_[0-9a-f]+$/,
  /^__wbg_length_[0-9a-f]+$/,
  /^__wbg_prototypesetcall_[0-9a-f]+$/,
  /^__wbg_new_from_slice_[0-9a-f]+$/,
  /^__wbg_set_[0-9a-f]+$/,
  /^__wbg_getRandomValues_[0-9a-f]+$/,
  /^__wbg___wbindgen_throw_[0-9a-f]+$/,
  /^__wbindgen_init_externref_table$/,
  /^__wbindgen_cast_[0-9a-f]+$/,
];
for (const item of WebAssembly.Module.imports(wasmModule)) {
  const allowed =
    item.module === "./reallyme_jose_wasm_bg.js" &&
    item.kind === "function" &&
    allowedImportNames.some((pattern) => pattern.test(item.name));
  if (!allowed) fail(`published WASM has an unreviewed import ${item.module}:${item.name}.`);
}

process.stdout.write(`npm pack contains ${entries[0].files.length} reviewed files.\n`);
