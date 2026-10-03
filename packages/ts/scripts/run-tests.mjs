// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const testFiles = [
  "test/reallyme-jose.test.mjs",
  "test/vector-conformance.test.mjs",
];
const minimumTests = 21;

for (const file of testFiles) {
  const source = readFileSync(file, "utf8");
  if (/\b(?:test|it|describe)\.(?:skip|todo|only)\s*\(/u.test(source)) {
    throw new Error(`${file} contains a disabled or exclusive test`);
  }
}

const result = spawnSync(
  process.execPath,
  ["--test", "--test-reporter=tap", ...testFiles],
  { encoding: "utf8" },
);
process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");
if (result.error || result.status !== 0) {
  process.exit(result.status ?? 1);
}

function summaryCount(label) {
  const match = result.stdout.match(new RegExp(`^# ${label} ([0-9]+)$`, "mu"));
  if (!match) throw new Error(`Node test output omitted the ${label} count`);
  return Number(match[1]);
}

if (summaryCount("tests") < minimumTests || summaryCount("skipped") !== 0
    || summaryCount("todo") !== 0) {
  throw new Error("TypeScript test count or execution status changed");
}
