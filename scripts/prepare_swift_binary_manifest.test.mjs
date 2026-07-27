#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { prepareManifest, SwiftManifestError } from "./prepare_swift_binary_manifest.mjs";

const fixture = `let ffiArtifactChecksum = "${"0".repeat(64)}"
let ffiArtifactVersion = "0.3.0"
let ffiArtifactLocalPathOverride = ""
`;
const checksum = "a".repeat(64);

test("binds version, checksum, and a normalized repository-local artifact", () => {
  const manifest = prepareManifest(fixture, "1.2.3", checksum, "build/swift/artifact.xcframework");
  assert.match(manifest, new RegExp(`ffiArtifactChecksum = "${checksum}"`, "u"));
  assert.match(manifest, /ffiArtifactVersion = "1\.2\.3"/u);
  assert.match(manifest, /ffiArtifactLocalPathOverride = "build\/swift\/artifact\.xcframework"/u);
});

test("rejects malformed release inputs", () => {
  for (const [version, digest, path] of [
    ["v1.2.3", checksum, ""],
    ["1.2.3", "A".repeat(64), ""],
    ["1.2.3", checksum, "../artifact"],
    ["1.2.3", checksum, "/tmp/artifact"],
  ]) {
    assert.throws(() => prepareManifest(fixture, version, digest, path), SwiftManifestError);
  }
});

test("rejects ambiguous manifest assignments", () => {
  assert.throws(
    () => prepareManifest(`${fixture}${fixture}`, "1.2.3", checksum),
    (error) => error instanceof SwiftManifestError && error.code.endsWith("assignment-count"),
  );
});
