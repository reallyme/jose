// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { schemaMessages } from "./read-proto-schema.mjs";

export function policyPresets(schema, header) {
  const presets = new Map([...schema.matchAll(/^\/\/ Contract preset: (\w+) (\w+) = (.+)$/gmu)]
    .map(([, message, name, json]) => [name, { message, json, value: JSON.parse(json) }]));
  const messages = new Map(schemaMessages(schema).map(({ name, body }) => [name, body]));
  const camel = (field) => field.replace(/_([a-z])/gu, (_, letter) => letter.toUpperCase());
  for (const { message, value } of presets.values()) {
    const fields = new Set([...messages.get(message).matchAll(/\w+ (\w+) =/gu)].map((match) => camel(match[1])));
    if (Object.keys(value).some((field) => !fields.has(field))) throw new TypeError("policy preset extends its schema message");
  }
  const encode = presets.get("standard_jwt_encode").value;
  const jwt = presets.get("standard_jwt_header").value;
  const temporal = presets.get("strict_temporal").value;
  const jwe = presets.get("openid4vp").value;
  const nativeVariant = (identity, selector) => {
    const prefix = schema.slice(0, schema.indexOf(`  ${identity} =`));
    const variant = new RegExp(`// Rust variant: ${selector}\\.(\\w+)[^\\n]*\\n$`, "u").exec(prefix)?.[1];
    if (variant === undefined) throw new TypeError("policy preset lacks a native selector binding");
    return `${selector}::${variant}`;
  };
  let source = header + "use crate::jwe::{JweKeyManagementAlgorithm, JweContentEncryptionAlgorithm};\n\n";
  source += `pub(crate) const JWT_TYPE: &str = ${JSON.stringify(encode.typ)};\n`;
  source += `pub(crate) const JWT_ACCEPTED_TYPES: &[&str] = &[${jwt.acceptedTypValues.map((value) => JSON.stringify(value)).join(", ")}];\n`;
  source += `pub(crate) const JWT_ALLOW_MISSING_TYPE: bool = ${jwt.allowMissingTyp};\npub(crate) const JWT_ALLOW_EMBEDDED_KEY: bool = ${jwt.allowEmbeddedKeyHeader};\n`;
  for (const [field, name] of [["requireExp", "REQUIRE_EXP"], ["requireNbf", "REQUIRE_NBF"], ["requireIat", "REQUIRE_IAT"]]) source += `pub(crate) const TEMPORAL_${name}: bool = ${temporal[field]};\n`;
  for (const field of ["clockSkewSeconds", "maxFutureIatSkewSeconds"]) {
    if (!schema.includes(`JOSE_CONTRACT_LIMIT_DEFAULT_TEMPORAL_SKEW_SECONDS = ${temporal[field]};`)) throw new TypeError("temporal preset and default skew differ");
  }
  source += `pub(crate) const OPENID_KEY_MANAGEMENT: &[JweKeyManagementAlgorithm] = &[${jwe.allowedKeyManagementAlgorithms.map((value) => nativeVariant(value, "JweKeyManagementAlgorithm")).join(", ")}];\n`;
  source += `pub(crate) const OPENID_CONTENT_ENCRYPTION: &[JweContentEncryptionAlgorithm] = &[${jwe.allowedContentEncryptionAlgorithms.map((value) => nativeVariant(value, "JweContentEncryptionAlgorithm")).join(", ")}];\n`;
  source += "#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn presets_match_generated_contract_and_native_defaults() -> Result<(), serde_json::Error> {\n";
  for (const [name, { message, json }] of presets) source += `        let ${name}: crate::api::contract::${message} = serde_json::from_str(r#"${json}"# )?;\n`;
  source += `        assert_eq!(standard_jwt_encode.typ.as_deref(), crate::jwt::JwtHeaderEncodeOptions::jwt().typ());
        let header = crate::jwt::JwtHeaderValidationOptions::standard_jwt();
        assert_eq!(standard_jwt_header.allow_missing_typ, header.allow_missing_typ());
        assert_eq!(standard_jwt_header.allow_embedded_key_header, header.allow_embedded_key_header());
        assert_eq!(standard_jwt_header.accepted_typ_values.iter().map(|value| value.as_str()).collect::<Vec<_>>(), header.accepted_typ_values());
        let temporal = crate::jwt::JwtTemporalValidationPolicy::strict();
        assert_eq!(strict_temporal.require_exp, temporal.require_exp());
        assert_eq!(strict_temporal.require_nbf, temporal.require_nbf());
        assert_eq!(strict_temporal.require_iat, temporal.require_iat());
        assert_eq!(strict_temporal.clock_skew_seconds, temporal.clock_skew_seconds());
        assert_eq!(strict_temporal.max_future_iat_skew_seconds, temporal.max_future_iat_skew_seconds());
        let profile = crate::jwe::CompactJwePolicy::openid4vp_direct_post_jwt();
        let _ = profile;
        assert_eq!(openid4vp.allowed_key_management_algorithms.as_ref(), OPENID_KEY_MANAGEMENT.iter().copied().map(crate::api::contract::JoseJweHeaderAlgorithm::from).map(buffa::EnumValue::from).collect::<Vec<_>>().as_slice());
        assert_eq!(openid4vp.allowed_content_encryption_algorithms.as_ref(), OPENID_CONTENT_ENCRYPTION.iter().copied().map(crate::api::contract::JoseJweContentEncryptionAlgorithm::from).map(buffa::EnumValue::from).collect::<Vec<_>>().as_slice());
        Ok(())
    }
}
`;
  const marker = "#[cfg(test)]\nmod tests {\n";
  const split = source.indexOf(marker);
  const tests = source.slice(split + marker.length).replace(/\n\}\n$/u, "\n").replace(/^ {4}/gmu, "")
    .replace("use super::*;", "use super::{OPENID_KEY_MANAGEMENT, OPENID_CONTENT_ENCRYPTION};");
  const production = source.slice(0, split) + '#[cfg(test)]\n#[path = "policy_defaults_tests.rs"]\nmod tests;\n';
  const files = new Map();
  for (const [name, content] of [["policy_defaults.rs", production], ["policy_defaults_tests.rs", header + tests]]) {
    const formatted = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], { input: content, encoding: "utf8" });
    if (formatted.status !== 0) throw new TypeError("formatting policy presets failed");
    files.set(`crates/jose/src/generated_contract/${name}`, formatted.stdout);
  }
  return files;
}
