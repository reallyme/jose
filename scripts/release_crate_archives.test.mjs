// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { publishArchives, registryMetadata, registryRequestBody, validateUploadResponse, verifiedArchives } from "./release_crate_archives.mjs";

const version = "0.5.0";
const source = "1".repeat(40);
const packages = ["reallyme-jose-proto", "reallyme-jose"];
const archives = packages.map((name) => {
  const bytes = Buffer.from(name);
  return {
    file: `${name}-${version}.crate`,
    metadata: { name, vers: version },
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes,
  };
});

test("crate upload framing preserves the reviewed archive bytes", () => {
  const [{ bytes, metadata }] = archives;
  const framed = registryRequestBody(metadata, bytes);
  const metadataSize = framed.readUInt32LE(0);
  const payloadSizeOffset = 4 + metadataSize;
  assert.deepEqual(JSON.parse(framed.subarray(4, payloadSizeOffset)), metadata);
  assert.equal(framed.readUInt32LE(payloadSizeOffset), bytes.length);
  assert.deepEqual(framed.subarray(payloadSizeOffset + 4), bytes);
  assert.throws(() => registryRequestBody(metadata, Buffer.alloc(0)), { message: "registry-request-size" });
});

test("only the exact archive inventory and release identity are accepted", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "reallyme-jose-crates-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const entries = archives.map(({ file, sha256, metadata, bytes }) => {
    writeFileSync(join(directory, file), bytes);
    return { file, sha256, metadata };
  });
  writeFileSync(join(directory, "crate-archives.json"),
    JSON.stringify({ schema: 1, version, sourceSha: source, entries }));
  assert.deepEqual(verifiedArchives(directory, version, source), archives);
  assert.throws(() => verifiedArchives(directory, version, "2".repeat(40)),
    { message: "artifact-release-identity-mismatch" });
  writeFileSync(join(directory, entries[0].file), "tampered archive");
  assert.throws(() => verifiedArchives(directory, version, source), { message: "archive-digest-mismatch" });
  writeFileSync(join(directory, "unlisted.crate"), "extra archive");
  assert.throws(() => verifiedArchives(directory, version, source), { message: "unexpected-artifact-inventory" });
});

test("registry promotion waits for the dependency checksum before uploading the consumer", async () => {
  const published = new Map();
  const events = [];
  await publishArchives(archives, "test", {
    digest: async (name) => {
      events.push(`read ${name}`);
      return published.get(name) ?? null;
    },
    upload: async (payload) => {
      const name = JSON.parse(payload.subarray(4, 4 + payload.readUInt32LE(0))).name;
      const artifact = archives.find((archive) => archive.metadata.name === name);
      events.push(`publish ${name}`);
      published.set(name, artifact.sha256);
      return 200;
    },
    pause: async () => {},
  });
  assert.deepEqual(events, packages.flatMap((name) => [`read ${name}`, `publish ${name}`, `read ${name}`]));
});

test("registry retries accept previously uploaded bytes only when their checksum matches", async () => {
  const unexpectedUpload = async () => assert.fail("existing version must never be uploaded again");
  const matching = async (name) => archives.find((archive) => archive.metadata.name === name).sha256;
  const mismatched = async () => "2".repeat(64);
  await publishArchives(archives, "test", { digest: matching, upload: unexpectedUpload });
  await assert.rejects(publishArchives(archives, "test", { digest: mismatched, upload: unexpectedUpload }),
    { message: "registry-archive-digest-mismatch" });
});


test("registry upload accepts the documented warnings response and rejects application errors", () => {
  assert.doesNotThrow(() => validateUploadResponse({ warnings: { invalid_categories: [], other: [] } }));
  assert.doesNotThrow(() => validateUploadResponse({}));
  for (const response of [null, [], { errors: [{ detail: "rejected" }] }]) {
    assert.throws(() => validateUploadResponse(response), { message: "registry-upload-rejected" });
  }
});

test("registry rate limiting backs off and still verifies the resulting digest", async () => {
  const [archive] = archives;
  const pauses = [];
  let calls = 0;
  await publishArchives([archive], "test", {
    digest: async () => calls === 2 ? archive.sha256 : null,
    upload: async () => ++calls === 1 ? 429 : 200,
    pause: async (ms) => { pauses.push(ms); },
  });
  assert.deepEqual(pauses, [60_000, 2_000]);
});


test("Cargo metadata preserves registry aliases and normalizes the versioned workspace dependency", () => {
  const runtime = {
    name: "reallyme-buffa",
    source: "registry+https://github.com/rust-lang/crates.io-index",
    req: "=0.1.1",
    rename: "buffa",
    features: ["json"],
    optional: true,
    uses_default_features: false,
    target: null,
    kind: null,
    registry: null,
  };
  const proto = { ...runtime, name: "reallyme-jose-proto", source: null,
    path: "/workspace/crates/proto", req: "^0.5.0", rename: null };
  const pkg = {
    name: "reallyme-jose", version, publish: null, readme: "README.md",
    license_file: null, links: null, dependencies: [runtime, proto],
  };
  const metadata = registryMetadata(pkg, version, "fixture");
  assert.equal(metadata.readme, "fixture");
  assert.deepEqual(metadata.deps[0], {
    name: "reallyme-buffa", version_req: "=0.1.1", features: ["json"],
    optional: true, default_features: false, target: null, kind: "normal",
    registry: null, explicit_name_in_toml: "buffa",
  });
  assert.equal(metadata.deps[1].version_req, "^0.5.0");
  assert.equal(metadata.deps[1].registry, null);
  assert.equal(Object.hasOwn(metadata.deps[1], "path"), false);
  assert.throws(() => registryMetadata({ ...pkg, dependencies: [{ ...proto, req: "*" }] }, version, "fixture"),
    { message: "unsupported-crate-dependency-source" });
});
