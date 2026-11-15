// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";

const snake = (value) => value.replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase();

// Selector declarations and protocol properties share the schema's ownership.
// In particular, a profile may deliberately accept only a subset of an enum.
export function nativeSelectors(schema, header) {
  const files = new Map();
  const modules = [];
  for (const [, annotations, contract, body] of schema.matchAll(/((?:\/\/ Rust selector: [^\n]+\n)+)enum (\w+) \{([\s\S]*?)\n\}/gu)) {
    const values = [...body.matchAll(/((?:\s*\/\/ Rust variant: [^\n]+\n)*)\s*([A-Z][A-Z0-9_]+) = (\d+);/gu)];
    for (const [, name, scope, branch, reason] of annotations.matchAll(/\/\/ Rust selector: (\w+); (public|crate|ffi); (\w+); (\w+)/gu)) {
      const cases = values.flatMap(([, metadata, value]) => [...metadata.matchAll(/\/\/ Rust variant: (\w+)\.(\w+)([^\n]*)/gu)]
        .filter((match) => match[1] === name)
        .map((match) => ({ variant: match[2], value, properties: Object.fromEntries([...match[3].matchAll(/; (\w+)=([^;\n]+)/gu)].map((entry) => [entry[1], entry[2]])) })));
      if (cases.length === 0 || new Set(cases.map(({ variant }) => variant)).size !== cases.length) throw new TypeError("invalid native selector binding");
      const ffi = scope === "ffi";
      const visibility = scope === "crate" ? "pub(crate)" : "pub";
      const path = `crates/${ffi ? "ffi" : "jose"}/src/generated_contract/${snake(name)}.rs`;
      if (!ffi) modules.push([snake(name), name, visibility]);
      const error = ffi ? "Self" : "crate::wire::JoseWireError";
      const rejection = ffi ? `Self::${reason}` : `crate::wire::JoseWireError::${branch}_internal(crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_${reason})`;
      let source = header + `use ${ffi ? "reallyme_jose" : "crate"}::api::contract::${contract} as Contract;\n\n`;
      source += `/// Closed native view of the schema's ${contract} selector.\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n${scope === "crate" ? "" : "#[non_exhaustive]\n"}${visibility} enum ${name} {\n`;
      source += cases.map(({ variant, properties }) => `    /// Schema-defined ${properties.label ?? variant} identity.\n    ${variant},`).join("\n") + "\n}\n\n";
      source += `impl TryFrom<buffa::EnumValue<${ffi ? "reallyme_jose" : "crate"}::api::contract::${contract}>> for ${name} {\n    type Error = ${error};\n    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {\n        match value.as_known() {\n`;
      source += cases.map(({ variant, value }) => `            Some(Contract::${value}) => Ok(Self::${variant}),`).join("\n");
      source += `\n            _ => Err(${rejection}),\n        }\n    }\n}\n\nimpl From<${name}> for Contract {\n    fn from(value: ${name}) -> Self {\n        match value {\n`;
      source += cases.map(({ variant, value }) => `            ${name}::${variant} => Self::${value},`).join("\n") + "\n        }\n    }\n}\n\n";
      const method = (methodName, returnType, expression, access = "pub(crate)") => {
        source += `impl ${name} {\n    /// Returns the schema-defined ${methodName.replaceAll("_", " ")}.\n    #[must_use]\n    ${access} const fn ${methodName}(self) -> ${returnType} {\n        match self {\n`;
        source += cases.map((entry) => `            Self::${entry.variant} => ${expression(entry)},`).join("\n") + "\n        }\n    }\n}\n\n";
      };
      if (cases.every(({ properties }) => properties.label !== undefined)) {
        if (name !== "JwsAlgorithm") method("as_str", "&'static str", ({ properties }) => JSON.stringify(properties.label), visibility);
        source += `impl ${name} {\n    pub(crate) fn from_jose_name(value: &str) -> Option<Self> {\n        match value {\n` + cases.map(({ variant, properties }) => `            ${JSON.stringify(properties.label)} => Some(Self::${variant}),`).join("\n") + "\n            _ => None,\n        }\n    }\n}\n\n";
      }
      if (name === "JwsAlgorithm") method("protected_header_json", "&'static [u8]", ({ properties }) => `br#"${JSON.stringify({ alg: properties.label })}"#`);
      if (cases.every(({ properties }) => properties.backend !== undefined)) method("backend", "crate::Algorithm", ({ properties }) => `crate::Algorithm::${properties.backend}`);
      if (cases.every(({ properties }) => properties.curve_id !== undefined)) method("named_curve", "crate::api::contract::JoseNamedCurve", ({ properties }) => `crate::api::contract::JoseNamedCurve::${properties.curve_id}`);
      if (cases.every(({ properties }) => properties.encoding_id !== undefined)) method("signature_encoding", "crate::api::contract::JoseSignatureEncoding", ({ properties }) => `crate::api::contract::JoseSignatureEncoding::${properties.encoding_id}`);
      if (cases.every(({ properties }) => properties.signature_bytes !== undefined)) {
        method("signature_bytes", "u32", ({ properties }) => properties.signature_bytes);
        method("signature_len", "usize", ({ properties }) => properties.signature_bytes);
      }
      if (cases.every(({ properties }) => properties.raw_provider !== undefined)) method("builtin_raw_provider", "bool", ({ properties }) => properties.raw_provider);
      if (cases.every(({ properties }) => properties.claim !== undefined)) method("as_str", "&'static str", ({ properties }) => JSON.stringify(properties.claim), visibility);
      if (cases.every(({ properties }) => properties.key_type !== undefined)) {
        source += `impl ${name} {\n    pub(crate) fn matches_jwk(self, key: &crate::Jwk) -> bool {\n        match (self, key) {\n` +
          cases.map(({ variant, properties }) => `            (Self::${variant}, crate::Jwk::${properties.key_type}(key)) => key.crv == ${JSON.stringify(properties.curve)},`).join("\n") +
          "\n            _ => false,\n        }\n    }\n}\n\n";
      }
      if (cases.every(({ properties }) => properties.header !== undefined)) {
        method("header_algorithm", "crate::jwe::JweKeyManagementAlgorithm", ({ properties }) => `crate::jwe::JweKeyManagementAlgorithm::${properties.header}`);
        method("jwk_curve", "Option<&'static str>", ({ properties }) => properties.curve === undefined ? "None" : `Some(${JSON.stringify(properties.curve)})`);
      }
      for (const property of ["key", "nonce", "tag"]) {
        if (cases.every(({ properties }) => properties[property] !== undefined)) method(`${property}_len`, "usize", ({ properties }) => properties[property], visibility);
      }
      if (ffi) method("code", "i32", ({ properties }) => properties.code, visibility);
      source += `#[cfg(test)]\nmod tests {\n    use super::*;\n    use buffa::Enumeration;\n\n    #[test]\n    fn schema_parity_and_invalid_values() {\n        let cases = [\n`;
      source += cases.map(({ variant, value }) => `            (Contract::${value}, ${name}::${variant}),`).join("\n") + "\n        ];\n";
      source += `        for (contract, native) in cases {\n            assert_eq!(${name}::try_from(buffa::EnumValue::from(contract)), Ok(native));\n            assert_eq!(Contract::from(native), contract);\n        }\n        for contract in Contract::values() {\n            assert_eq!(${name}::try_from(buffa::EnumValue::from(*contract)).is_ok(), cases.iter().any(|(value, _)| value == contract));\n        }\n        for invalid in [0, -1, i32::MIN, i32::MAX] {\n            assert!(${name}::try_from(buffa::EnumValue::from(invalid)).is_err());\n        }\n    }\n}\n`;
      const marker = "#[cfg(test)]\nmod tests {\n";
      const split = source.indexOf(marker);
      const tests = source.slice(split + marker.length).replace(/\n\}\n$/u, "\n").replace(/^ {4}/gmu, "")
        .replace("use super::*;", `use super::{Contract, ${name}};`);
      const production = source.slice(0, split) + `#[cfg(test)]\n#[path = "${snake(name)}_tests.rs"]\nmod tests;\n`;
      for (const [outputPath, content] of [[path, production], [path.replace(/\.rs$/u, "_tests.rs"), header + tests]]) {
        const formatted = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], { input: content, encoding: "utf8" });
        if (formatted.status !== 0) throw new TypeError("formatting native selectors failed");
        files.set(outputPath, formatted.stdout);
      }
    }
  }
  const moduleSource = header + "pub(crate) mod policy_defaults;\n" + modules.map(([module]) => `mod ${module};`).join("\n") + "\n\n" + modules.map(([module, name, visibility]) => `${visibility} use ${module}::${name};`).join("\n") + "\n";
  const formattedModule = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], { input: moduleSource, encoding: "utf8" });
  if (formattedModule.status !== 0) throw new TypeError("formatting native selector module failed");
  files.set("crates/jose/src/generated_contract/mod.rs", formattedModule.stdout);
  return files;
}
