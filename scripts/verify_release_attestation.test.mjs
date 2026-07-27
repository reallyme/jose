#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  ReleaseAttestationError,
  requireLatestSuccessfulRun,
} from "./verify_release_attestation.mjs";

const releaseSha = "a".repeat(40);
const run = (overrides = {}) => ({
  attempt: 1,
  conclusion: "success",
  databaseId: 100,
  displayTitle: "Swift package preflight 0.3.0",
  event: "workflow_dispatch",
  headBranch: "main",
  headSha: releaseSha,
  status: "completed",
  ...overrides,
});

test("accepts the latest successful version-bound preflight", () => {
  const selected = requireLatestSuccessfulRun(
    [run({ attempt: 1 }), run({ attempt: 2 })],
    releaseSha,
    "swift-package-preflight.yml",
    "0.3.0",
  );
  assert.equal(selected.attempt, 2);
});

test("accepts a version-bound crates package preflight", () => {
  const selected = requireLatestSuccessfulRun(
    [run({ displayTitle: "Crates package preflight 0.3.0" })],
    releaseSha,
    "crates-package-preflight.yml",
    "0.3.0",
  );
  assert.equal(selected.databaseId, 100);
});

test("accepts a version-bound npm package preflight", () => {
  const selected = requireLatestSuccessfulRun(
    [run({ displayTitle: "npm package preflight 0.3.0" })],
    releaseSha,
    "npm-package-preflight.yml",
    "0.3.0",
  );
  assert.equal(selected.databaseId, 100);
});

test("rejects a preflight for another version", () => {
  assert.throws(
    () => requireLatestSuccessfulRun(
      [run({ displayTitle: "Swift package preflight 0.2.0" })],
      releaseSha,
      "swift-package-preflight.yml",
      "0.3.0",
    ),
    (error) => error instanceof ReleaseAttestationError && error.code === "preflight-version-mismatch",
  );
});

test("a newer failed attempt invalidates an older success", () => {
  assert.throws(
    () => requireLatestSuccessfulRun(
      [run(), run({ attempt: 2, conclusion: "failure", databaseId: 101 })],
      releaseSha,
      "swift-package-preflight.yml",
      "0.3.0",
    ),
    ReleaseAttestationError,
  );
});

test("rejects pull-request and wrong-SHA evidence", () => {
  for (const evidence of [
    run({ event: "pull_request", headBranch: "feature" }),
    run({ headSha: "b".repeat(40) }),
  ]) {
    assert.throws(
      () => requireLatestSuccessfulRun(
        [evidence], releaseSha, "swift-package-preflight.yml", "0.3.0",
      ),
      ReleaseAttestationError,
    );
  }
});
