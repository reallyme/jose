// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("formal proofs require an explicit manual dispatch", () => {
  const config = JSON.parse(read(".github/release-readiness.json"));
  assert.equal(config.lanes.formal.mode, "manual");
  assert.match(read(".github/workflows/formal-verification.yml"), /\non:\n  workflow_dispatch:\n\npermissions:/u);
});

test("every proof checkout selects the dispatched revision", () => {
  const workflow = read(".github/workflows/formal-verification.yml");
  const checkouts = [...workflow.matchAll(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n\s+with:\n((?:[ \t]+[^\n]*\n)+)/gu)];
  assert.ok(checkouts.length > 0);
  for (const [, inputs] of checkouts) {
    assert.match(inputs, /ref: \$\{\{ github[.]sha \}\}/u);
    assert.match(inputs, /persist-credentials: false/u);
  }
});

test("required CI omits the manual proof workflow", () => {
  assert.doesNotMatch(read(".github/workflows/ci.yml"), /uses: [^\n]*formal-verification[.]yml/u);
});

test("manual dispatch retains the complete proof runners", () => {
  const workflow = read(".github/workflows/formal-verification.yml");
  for (const runner of ["scripts/check-formal.sh"]) assert.ok(workflow.includes(runner));
  assert.match(workflow, /git rev-parse --verify HEAD/u);
  assert.doesNotMatch(workflow, /verified_sha:/u);
});
