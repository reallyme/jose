// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { requireGeneratorVersions } from "./generate-jose-proto.mjs";

test("both exact published generator identities are required", () => {
  const calls = [];
  requireGeneratorVersions((name) => { calls.push(name); return { status: 0, stdout: `${name} 0.1.3\n` }; });
  assert.deepEqual(calls, ["protoc-gen-reallyme-buffa", "protoc-gen-reallyme-buffa-packaging"]);
  for (const response of [
    { status: 0, stdout: "protoc-gen-buffa 0.1.3\n" },
    { status: 0, stdout: "protoc-gen-reallyme-buffa 0.1.2\n" },
    { status: 1, stdout: "protoc-gen-reallyme-buffa 0.1.3\n" },
    { status: null, error: new TypeError("missing tool"), stdout: "" },
  ]) assert.throws(() => requireGeneratorVersions(() => response), TypeError);
});
