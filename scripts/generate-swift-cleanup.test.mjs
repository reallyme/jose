// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { swiftCleanup } from "./generate-swift-cleanup.mjs";
import { schemaMessages } from "./read-proto-schema.mjs";

const schema = readFileSync(new URL("../crates/proto/proto/reallyme/jose/v1/jose.proto", import.meta.url), "utf8");
const header = "// Schema-derived cleanup.\n\n";
const source = (files, name) => files.get(`packages/swift/Sources/ReallyMeJOSE/${name}`);

test("every schema owner has exactly one cleanup overload within the source limit", () => {
  const files = swiftCleanup(schema, header);
  const owners = [];
  for (const content of files.values()) {
    assert.ok(content.split("\n").length <= 500);
    assert.ok(content.startsWith(header + "import ReallyMeJOSEProto\n\n"));
    for (const [, name] of content.matchAll(/^func clearSensitiveFields\(_ message: inout ReallyMeProto(\w+)\)/gmu)) owners.push(name);
  }
  assert.equal(new Set(owners).size, owners.length);
  assert.deepEqual(owners.sort(), schemaMessages(schema).map(({ name }) => name).sort());
});

test("nested and repeated owners are cleared across module boundaries before reset", () => {
  const files = swiftCleanup(`
message JoseJwsResult {
  bytes payload = 1;
}
message JoseJwtRequest {
  optional JoseJwsResult input = 1;
  repeated JoseJwsResult receipts = 2;
  bytes private_key = 3;
}
message JoseOperationRequest {
  oneof operation {
    JoseJwtRequest jwt = 1;
    uint32 selector = 2;
  }
}
`, header);
  const jws = source(files, "ClearJwsMemory.swift");
  assert.match(jws, /ReallyMeJOSEMemory\.clearOwned\(&message\.payload\)/u);
  const jwt = source(files, "ClearJwtMemory.swift");
  for (const cleanup of [
    "if message.hasInput { clearSensitiveFields(&message.input) }",
    "for index in message.receipts.indices { clearSensitiveFields(&message.receipts[index]) }",
    "ReallyMeJOSEMemory.clearOwned(&message.privateKey)",
  ]) {
    assert.ok(jwt.includes(cleanup));
    assert.ok(jwt.indexOf(cleanup) < jwt.indexOf("message = ReallyMeProtoJoseJwtRequest()"));
  }
  const operation = source(files, "ClearOperationMemory.swift");
  assert.match(operation, /case \.jwt: clearSensitiveFields\(&message\.jwt\)/u);
  assert.match(operation, /case \.selector: break/u);
  assert.match(operation, /case nil: break/u);
  assert.ok(operation.indexOf("switch message.operation") < operation.indexOf("message = ReallyMeProtoJoseOperationRequest()"));
});

test("new shared message names retain cleanup instead of falling outside a family", () => {
  const files = swiftCleanup("message FutureOwner {\n  bytes secret = 1;\n}\n", header);
  const shared = source(files, "ContractMemory.swift");
  assert.match(shared, /func clearSensitiveFields\(_ message: inout ReallyMeProtoFutureOwner\)/u);
  assert.match(shared, /ReallyMeJOSEMemory\.clearOwned\(&message\.secret\)/u);
  assert.match(shared, /message = ReallyMeProtoFutureOwner\(\)/u);
  assert.throws(() => swiftCleanup("message Broken {", header), TypeError);
});

test("cleanup generation is deterministic and does not retain prior schema owners", () => {
  const first = swiftCleanup(schema, header);
  assert.deepEqual(swiftCleanup(schema, header), first);
  const next = swiftCleanup("message Replacement {\n  bytes secret = 1;\n}\n", header);
  assert.ok([...next.values()].every((content) => !content.includes("ReallyMeProtoJoseOperationRequest")));
  assert.deepEqual(swiftCleanup(schema, header), first);
});
