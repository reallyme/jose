#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
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
const allowedFiles = new Set([
  "package/LICENSE", "package/NOTICE", "package/README.md", "package/package.json",
  "package/dist/boundary.d.ts", "package/dist/boundary.js",
  "package/dist/errors.d.ts", "package/dist/errors.js",
  "package/dist/facade-support.d.ts", "package/dist/facade-support.js",
  "package/dist/facade.d.ts", "package/dist/facade.js",
  "package/dist/index.d.ts", "package/dist/index.js",
  "package/dist/memory.d.ts", "package/dist/memory.js",
  "package/dist/proto.d.ts", "package/dist/proto.js",
  "package/dist/proto/generated/reallyme/jose/v1/jose_pb.d.ts",
  "package/dist/proto/generated/reallyme/jose/v1/jose_pb.js",
  "package/dist/provider.d.ts", "package/dist/provider.js",
  "package/dist/validate.d.ts", "package/dist/validate.js",
  "package/dist/wasm/LICENSE", "package/dist/wasm/reallyme_jose_wasm_bg.wasm",
  "package/dist/wasm/reallyme_jose_wasm.js",
  "package/dist/wasmModuleTypes.d.ts", "package/dist/wasmModuleTypes.js",
]);

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const snapshotDist = () => {
  const files = [];
  const visit = (directory, relative) => {
    for (const name of readdirSync(directory).sort()) {
      const nextRelative = relative ? `${relative}/${name}` : name;
      const path = join(directory, name);
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) fail("dist must not contain symbolic links.");
      if (metadata.isDirectory()) {
        visit(path, nextRelative);
      } else if (metadata.isFile()) {
        files.push([nextRelative, createHash("sha256").update(readFileSync(path)).digest("hex")]);
      } else {
        fail("dist contains an unsupported filesystem entry.");
      }
    }
  };
  visit(resolve(packageDirectory, "dist"), "");
  return JSON.stringify(files);
};

const beforeBuild = snapshotDist();
const build = spawnSync("npm", ["run", "build"], {
  cwd: packageDirectory,
  encoding: "utf8",
});
if (build.status !== 0) {
  process.stdout.write(build.stdout);
  process.stderr.write(build.stderr);
  fail("package rebuild failed.");
}
if (beforeBuild !== snapshotDist()) {
  fail("dist differs from a clean rebuild of the source tree.");
}

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
const unexpectedFiles = [...names].filter((file) => !allowedFiles.has(file));
if (unexpectedFiles.length !== 0 || names.size !== allowedFiles.size) {
  fail(`npm package contains an unreviewed file inventory: ${unexpectedFiles.join(", ")}`);
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
