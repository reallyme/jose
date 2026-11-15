// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { assertProtobufContract, checkProtobufContract } from "./check-protobuf-contract.mjs";
import { schemaMessages } from "./read-proto-schema.mjs";

const fixture = () => ({
  schema: `message JoseOperationRequest {
  oneof operation {
    // Rust adapter: value.rs#read
    ReadRequest read = 1000;
  }
}
message JoseOperationResponse {
  oneof response {
    ReadResponse read = 1000;
  }
}
message ReadRequest {}
message ReadResponse {}`,
  sources: new Map([["value.rs", "pub fn read() {}"]]),
  dispatcher: "RequestOperation::Read(request)", responseBuilders: "Response::Read(result)",
  failures: "", errorTests: "",
});

test("repository public operations remain bound to the schema", () => checkProtobufContract());
test("paired operation identity is accepted", () => assert.doesNotThrow(() => assertProtobufContract(fixture())));
test("an unrepresented public operation fails", () => {
  const value = fixture(); value.sources.set("extra.rs", "pub fn extra() {}");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("a phantom schema adapter fails", () => {
  const value = fixture(); value.sources.clear();
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("a changed result number fails", () => {
  const value = fixture(); value.schema = value.schema.replace("ReadResponse read = 1000", "ReadResponse read = 1001");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("a duplicated dispatch arm fails", () => {
  const value = fixture(); value.dispatcher += " RequestOperation::Read(other)";
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("an independent public policy fails", () => {
  const value = fixture(); value.sources.set("policy.rs", "pub struct NewPolicy {}");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("a native enum without a schema conversion fails", () => {
  const value = fixture(); value.sources.set("choice.rs", "pub enum Choice { One }");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("an unmapped native error fails", () => {
  const value = fixture(); value.sources.set("error.rs", "pub enum DomainError {\n    Invalid,\n}");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("schema comments cannot hide or invent message boundaries", () => {
  assert.deepEqual(schemaMessages("// message Fake {\nmessage Empty {}\nmessage Full {\n // }\n bytes value = 1;\n}" ).map(({ name }) => name), ["Empty", "Full"]);
  assert.throws(() => schemaMessages("message Broken {"), TypeError);
});
test("unreachable schema vocabularies fail", () => {
  const value = fixture(); value.schema += "\nmessage Unused {}";
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("handmade presence flags fail", () => {
  const value = fixture(); value.schema = value.schema.replace("message ReadRequest {}", "message ReadRequest {\n bool has_key = 1;\n}");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("sensitive scalar ownership must be declared in the schema", () => {
  const value = fixture(); value.schema = value.schema.replace("message ReadRequest {}", "message ReadRequest {\n bytes key = 1;\n}");
  assert.throws(() => assertProtobufContract(value), TypeError);
  value.schema = value.schema.replace(" bytes key", " // SENSITIVE: signing material.\n bytes key");
  assert.doesNotThrow(() => assertProtobufContract(value));
});
test("one native failure cannot name two public reasons", () => {
  const value = fixture(); value.schema += "\n// Rust failure: DomainError::Invalid\n// Rust failure: DomainError::Invalid\n";
  assert.throws(() => assertProtobufContract(value), TypeError);
});

test("public wire operations and qualified functions cannot bypass bindings", () => {
  for (const path of ["api.rs", "wire.rs", "wire/extra.rs", "operation_contract/providers.rs"]) {
    for (const declaration of ["pub fn extra() {}", "pub const fn extra() {}", "pub async fn extra() {}", 'pub unsafe extern "C" fn extra() {}']) {
      const value = fixture(); value.sources.set(path, declaration);
      assert.throws(() => assertProtobufContract(value), TypeError);
    }
  }
});
test("public traits constants and aliases must be reachable", () => {
  for (const declaration of ["pub trait Provider {}", "pub const LIMIT: usize = 1;", "pub type Outcome = u8;"]) {
    const value = fixture(); value.sources.set("new.rs", declaration);
    assert.throws(() => assertProtobufContract(value), TypeError);
  }
});
test("phantom native views and capabilities fail", () => {
  for (const kind of ["view", "capability"]) {
    const value = fixture(); value.schema = `// Rust ${kind}: new.rs#New\n` + value.schema;
    assert.throws(() => assertProtobufContract(value), TypeError);
  }
});
test("native enum conversions must consume the generated enumeration exactly once", () => {
  const value = fixture();
  value.schema = value.schema.replace("message ReadRequest {}", "message ReadRequest {\n Choice choice = 1;\n}\nenum Choice {\n CHOICE_UNSPECIFIED = 0;\n CHOICE_ONE = 100;\n}");
  value.sources.set("choice.rs", "pub enum NativeChoice { One }\nimpl TryFrom<String> for NativeChoice {}");
  assert.throws(() => assertProtobufContract(value), TypeError);
  const conversion = "pub enum NativeChoice { One }\nimpl TryFrom<EnumValue<Choice>> for NativeChoice {}";
  value.sources.set("choice.rs", conversion);
  assert.doesNotThrow(() => assertProtobufContract(value));
  value.sources.set("choice.rs", conversion + "\nimpl TryFrom<String> for NativeChoice {}");
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("bound public value fields cannot extend the schema silently", () => {
  const value = fixture();
  value.schema = value.schema.replace("message ReadRequest {}", "// Rust view: value.rs#Policy\nmessage ReadRequest {\n bool enabled = 1;\n}");
  value.sources.set("value.rs", "pub fn read() {}\npub struct Policy {\n pub enabled: bool,\n}");
  assert.doesNotThrow(() => assertProtobufContract(value));
  value.sources.set("value.rs", value.sources.get("value.rs").replace("pub enabled: bool,", "pub enabled: bool,\n pub unchecked: bool,"));
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("a public limit cannot diverge from the schema value", () => {
  const value = fixture();
  value.schema = value.schema.replace("message ReadRequest {}", `message ReadRequest {
 JoseContractLimit limit = 1;
}
enum JoseContractLimit {
 // Rust constant: value.rs#LIMIT = COMPACT_BYTES
 JOSE_CONTRACT_LIMIT_UNSPECIFIED = 0;
 JOSE_CONTRACT_LIMIT_COMPACT_BYTES = 1024;
}`);
  value.sources.set("value.rs", "pub fn read() {}\npub const LIMIT: usize = reallyme_jose_proto::generated::contract_values::COMPACT_BYTES;");
  assert.doesNotThrow(() => assertProtobufContract(value));
  value.sources.set("value.rs", value.sources.get("value.rs").replace("::COMPACT_BYTES;", "::COMPACT_BYTES + 1;"));
  assert.throws(() => assertProtobufContract(value), TypeError);
});
test("struct-shaped error variants cannot escape mapping checks", () => {
  const value = fixture(); value.sources.set("error.rs", "pub enum DomainError {\n    Invalid { reason: u32 },\n}");
  assert.throws(() => assertProtobufContract(value), TypeError);
});

test("native selector profiles cannot acquire a Rust-only variant", () => {
  const value = fixture();
  value.schema = value.schema.replace("message ReadRequest {}", "message ReadRequest { Choice choice = 1; }") + `
// Rust selector: NativeChoice; public; provider; PROVIDER_UNSUPPORTED
enum Choice {
  CHOICE_UNSPECIFIED = 0;
  // Rust variant: NativeChoice.One
  CHOICE_ONE = 100;
}`;
  value.sources.set("choice.rs", `pub enum NativeChoice {
    One,
}
impl TryFrom<EnumValue<Choice>> for NativeChoice {}
impl From<NativeChoice> for Choice {}`);
  assert.doesNotThrow(() => assertProtobufContract(value));
  value.sources.set("choice.rs", value.sources.get("choice.rs").replace("    One,", "    One,\n    Extra,"));
  assert.throws(() => assertProtobufContract(value), /native selector variants differ/u);
});
