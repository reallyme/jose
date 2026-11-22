// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { assertPublicationPaths, assertPublicationPrivacy } from "./check-publication-privacy.mjs";

test("publication paths use repository exceptions and reject ignored dist output", () => {
  assert.doesNotThrow(() => assertPublicationPaths(["src/lib.rs"], { prefix: "crates/jose" }));
  assert.doesNotThrow(() => assertPublicationPaths(["src/generated/model.rs"], { prefix: "crates/proto" }));
  assert.throws(() => assertPublicationPaths(["dist/index.js"], { prefix: "packages/ts" }), { code: "publication-privacy-rejected" });
  assert.throws(() => assertPublicationPaths(["AGENTS.md"]), { code: "publication-privacy-rejected" });
  assert.throws(() => assertPublicationPaths(["../outside"]), { code: "publication-privacy-rejected" });
});

test("publication directories preserve local contents when rejected", (t) => {
  const root = mkdtempSync(join(tmpdir(), "publication-privacy-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, "AGENTS.md"), "synthetic fixture");
  assert.throws(() => assertPublicationPrivacy(root), { code: "publication-privacy-rejected" });
});

test("publication boundary rejects malformed arguments", () => {
  for (const value of [null, undefined, 42, ["bad\0path"]]) {
    assert.throws(() => assertPublicationPaths(value), { code: "publication-privacy-rejected" });
  }
  assert.throws(() => assertPublicationPrivacy(""), { code: "publication-privacy-rejected" });
});
