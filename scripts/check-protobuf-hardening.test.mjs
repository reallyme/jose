// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { assertProtobufHardening, checkProtobufHardening } from "./check-protobuf-hardening.mjs";
const fixture = () => ({
  schema: readFileSync(new URL("../crates/proto/proto/reallyme/jose/v1/jose.proto", import.meta.url), "utf8"),
  owned: readFileSync(new URL("../crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs", import.meta.url), "utf8"),
  views: readFileSync(new URL("../crates/proto/src/generated/buffa/reallyme.jose.v1.jose.__view.rs", import.meta.url), "utf8"),
  config: readFileSync(new URL("../buf.gen.yaml", import.meta.url), "utf8"),
});
test("native cleanup profiles preserve every generated owner", () => checkProtobufHardening());
test("removing native wipe or view redaction fails", () => {
  for (const [source, before, after] of [
    ["owned", "::buffa::sensitive::Zeroize::zeroize(&mut self.private_key);", ""],
    ["views", '.field("private_key", &::core::format_args!("[REDACTED]"))', '.field("private_key", &self.private_key)'],
  ]) {
    const value = fixture(); assert.ok(value[source].includes(before)); value[source] = value[source].replaceAll(before, after);
    assert.throws(() => assertProtobufHardening(value), TypeError);
  }
});
test("native configuration cannot lose a cleanup or JSON policy", () => {
  for (const option of ["zeroize_in=.reallyme.jose.v1", "borrowed_views_only_in=.reallyme.jose.v1", "unknown_fields=false", "deny_unknown_json_fields=true",
    "json_policy_type=crate::SecretBytes", "json_policy_type=crate::SecretString"]) {
    const value = fixture(); value.config = value.config.replace(option, "");
    assert.throws(() => assertProtobufHardening(value), TypeError);
  }
});
test("ordinary scalar storage and obsolete patches fail the native audit", () => {
  const value = fixture(); value.owned = value.owned.replace("pub private_key: crate::SecretBytes", "pub private_key: Vec<u8>");
  assert.throws(() => assertProtobufHardening(value), TypeError);
  value.owned = fixture().owned + "\nfn __reallyme_zeroize_unknown_fields() {}";
  assert.throws(() => assertProtobufHardening(value), TypeError);
});

test("ordinary owned view generation fails the native audit", () => {
  const value = fixture();
  value.views += "\npub struct JoseJwsSignRequestOwnedView(::buffa::OwnedView<JoseJwsSignRequestView<'static>>);";
  assert.throws(() => assertProtobufHardening(value), TypeError);
});
