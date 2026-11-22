#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { sdkVerification } from "./generate-sdk-verification.mjs";
import { policyPresets } from "./generate-policy-presets.mjs";
import { nativeSelectors } from "./generate-native-selectors.mjs";
import { swiftCleanup } from "./generate-swift-cleanup.mjs";

const root = new URL("../", import.meta.url);
const header = readFileSync(new URL(import.meta.url), "utf8").split("\n").slice(1, 4).join("\n") +
  "\n\n// Derived from the protobuf contract. Change the schema and regenerate.\n\n";
const camel = (value) => value.toLowerCase().replace(/_([a-z0-9])/gu, (_match, letter) => letter.toUpperCase());
const swift = (value) => camel(value).replaceAll("Json", "JSON").replaceAll("Base64url", "Base64URL");
const swiftNumber = (value) => value.replace(/\B(?=(?:\d{3})+(?!\d))/gu, "_");

function enumeration(schema, name, prefix) {
  const body = new RegExp(`enum ${name} \\{([\\s\\S]*?)\\n\\}`, "u").exec(schema)?.[1];
  if (body === undefined) throw new TypeError("required schema enumeration missing");
  return [...body.matchAll(/^\s*([A-Z][A-Z_0-9]+)\s*=\s*(\d+);/gmu)]
    .map((match) => ({ name: match[1].slice(prefix.length), number: match[2] }))
    .filter((value) => value.name !== "UNSPECIFIED");
}

function typescriptSdkErrorCodes(schema) {
  const prefix = "JOSE_SDK_ERROR_CODE_";
  const values = enumeration(schema, "JoseSdkErrorCode", prefix);
  const names = new Set(values.map(({ name }) => name));
  const entries = [...schema.matchAll(/^\s*\/\/ TypeScript SDK code: ([a-z]+(?:-[a-z]+)*)\n\s+JOSE_SDK_ERROR_CODE_([A-Z_]+)\s*=/gmu)];
  const declarations = [...schema.matchAll(/\/\/ TypeScript SDK code:/gu)];
  if (entries.length === 0 || entries.length !== declarations.length ||
      entries.some(([, , name]) => !names.has(name)) ||
      new Set(entries.map(([, code]) => code)).size !== entries.length ||
      new Set(entries.map(([, , name]) => name)).size !== entries.length) {
    throw new TypeError("invalid TypeScript SDK error code binding");
  }
  return `/** Stable TypeScript error labels declared by the SDK contract. */\nexport const ReallyMeJoseSdkErrorCode = Object.freeze({\n` +
    entries.map(([, code, name]) => `  ${name}: ${JSON.stringify(code)},`).join("\n") +
    `\n});\n\nexport type ReallyMeJoseSdkErrorCode =\n  typeof ReallyMeJoseSdkErrorCode[keyof typeof ReallyMeJoseSdkErrorCode];\n\n` +
    `export const sdkErrorSchemaCodes: Readonly<Record<ReallyMeJoseSdkErrorCode, JoseSdkErrorCode>> = Object.freeze({\n` +
    entries.map(([, , name]) => `  [ReallyMeJoseSdkErrorCode.${name}]: JoseSdkErrorCode.${name},`).join("\n") +
    "\n});\n\n";
}

export function generateContractValues({ check = false } = {}) {
  const schema = readFileSync(new URL("crates/proto/proto/reallyme/jose/v1/jose.proto", root), "utf8");
  const limits = [
    ...enumeration(schema, "JoseContractLimit", "JOSE_CONTRACT_LIMIT_"),
    ...enumeration(schema, "JoseJwtPolicyLimit", "JOSE_JWT_POLICY_LIMIT_"),
  ];
  const abi = enumeration(schema, "JoseNativeAbiVersion", "JOSE_NATIVE_ABI_VERSION_");
  if (abi.length !== 1) throw new TypeError("exactly one current native ABI is required");
  const packageName = /^package ([a-z0-9_.]+);$/mu.exec(schema)?.[1];
  if (packageName === undefined) throw new TypeError("schema package missing");
  const reasons = enumeration(schema, "JoseErrorReason", "JOSE_ERROR_REASON_");
  const branches = enumeration(schema, "JoseErrorBranch", "JOSE_ERROR_BRANCH_");
  const branch = (name) => name.startsWith("PROVIDER_") ? "provider" : name.startsWith("BACKEND_") ? "backend" : "primitive";
  const title = (value) => value[0].toUpperCase() + value.slice(1);
  const failureBindings = new Map();
  let pendingFailures = [];
  for (const line of schema.split("\n")) {
    const binding = /^\s*\/\/ Rust failure: (\w+::\w+(?:\(_\))?)$/u.exec(line);
    if (binding !== null) pendingFailures.push(binding[1]);
    const reason = /^\s*(JOSE_ERROR_REASON_[A-Z0-9_]+)\s*=/u.exec(line);
    if (reason === null) continue;
    for (const identity of pendingFailures) {
      if (failureBindings.has(identity)) throw new TypeError("native failure has multiple schema reasons");
      failureBindings.set(identity, reason[1]);
    }
    pendingFailures = [];
  }
  if (pendingFailures.length !== 0) throw new TypeError("native failure lacks a schema reason");
  let failureSource = header + `//! Total native failure mappings derived from schema bindings.

use crate::jwe::JweError;
use crate::jws::suites::{eddsa::JwsEddsaError, es256::JwsEs256Error};
use crate::jwt::JwtError;
use crate::jwk::JwkThumbprintErrorReason;
use crate::operation_contract::jws::{JwsSignError, JwsSignErrorReason, JwsVerifyError, JwsVerifyErrorReason};
use crate::wire::{JoseWireError, JoseWireErrorConstructionError};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::JoseErrorReason;

`;
  for (const [name, input, matched] of [
    ["construction", "JoseWireErrorConstructionError", "JoseWireErrorConstructionError"],
    ["jwe", "JweError", "JweError"], ["jwt", "JwtError", "JwtError"],
    ["jwk_thumbprint", "JwkThumbprintErrorReason", "JwkThumbprintErrorReason"],
    ["jws_sign", "JwsSignError", "JwsSignErrorReason"], ["jws_verify", "JwsVerifyError", "JwsVerifyErrorReason"],
    ["eddsa", "JwsEddsaError", "JwsEddsaError"], ["es256", "JwsEs256Error", "JwsEs256Error"],
  ]) {
    const direct = name === "construction";
    const bindings = [...failureBindings].filter(([identity]) => identity.startsWith(`${matched}::`));
    if (bindings.length === 0) throw new TypeError("native failure family lacks bindings");
    failureSource += `pub(crate) const fn ${name}(error: &${input}) -> ${direct ? "JoseErrorReason" : "JoseWireError"} {\n    match ${input === matched ? "error" : "error.reason()"} {\n`;
    failureSource += bindings.map(([identity, reason]) => `        ${identity} => ${direct ? `JoseErrorReason::${reason}` : `JoseWireError::${branch(reason.slice("JOSE_ERROR_REASON_".length))}_internal(JoseErrorReason::${reason})`},`).join("\n");
    failureSource += "\n    }\n}\n\n";
  }
  const rust = header + "use super::proto::reallyme::jose::v1::{JoseErrorReason, JoseErrorBranch};\n\n" +
    `/// Current native function ABI.\npub const NATIVE_ABI_VERSION: u32 = ${abi[0].number};\n\n` +
    limits.map(({ name, number }) => `/// Schema-defined ${name.toLowerCase().replaceAll("_", " ")}.\npub const ${name}: ${name.endsWith("SECONDS") ? "u64" : name.endsWith("DEPTH") ? "u32" : "usize"} = ${number};`).join("\n") +
    "\n\n/// Returns the branch assigned by the schema's reason family.\n#[must_use]\npub const fn error_branch(reason: JoseErrorReason) -> Option<JoseErrorBranch> {\n    match reason {\n" +
    reasons.map(({ name }) => `        JoseErrorReason::JOSE_ERROR_REASON_${name} => Some(JoseErrorBranch::${title(branch(name))}),`).join("\n") +
    "\n        JoseErrorReason::Unspecified => None,\n    }\n}\n";
  const temporalDefaults = JSON.parse(/\/\/ Contract preset: JoseJwtTemporalOptions strict_temporal = (.+)/u.exec(schema)[1]);
  const typescript = header + 'import { JoseErrorReason, JoseSdkErrorCode } from "./generated/reallyme/jose/v1/jose_pb.js";\n\n' +
    typescriptSdkErrorCodes(schema) +
    `export type ReallyMeJoseErrorBranch = ${branches.map(({ name }) => `"${name.toLowerCase()}"`).join(" | ")};\n\n` +
    `export const STRICT_TEMPORAL_DEFAULTS = Object.freeze({ requireExp: ${temporalDefaults.requireExp}, requireNbf: ${temporalDefaults.requireNbf}, requireIat: ${temporalDefaults.requireIat}, clockSkewSeconds: ${temporalDefaults.clockSkewSeconds}n, maxFutureIatSkewSeconds: ${temporalDefaults.maxFutureIatSkewSeconds}n });\n\n` +
    limits.map(({ name, number }) => `export const ${name} = ${number}${name.endsWith("SECONDS") ? "n" : ""};`).join("\n") +
    '\n\nexport const errorBranch = (reason: JoseErrorReason): ReallyMeJoseErrorBranch | undefined => {\n  switch (reason) {\n' +
    reasons.map(({ name }) => `    case JoseErrorReason.${name}: return "${branch(name)}";`).join("\n") +
    "\n    default: return undefined;\n  }\n};\n";
  const swiftSource = header + "enum JoseContractValues {\n" +
    `  static let nativeAbiVersion: UInt32 = ${abi[0].number}\n` +
    limits.map(({ name, number }) => `  static let ${camel(name)}: ${name.endsWith("SECONDS") ? "UInt64" : "Int"} = ${swiftNumber(number)}`).join("\n") +
    "\n}\n\n/// Schema-derived stable reason codes without caller data.\npublic enum ReallyMeJOSEErrorReason: Int, Sendable, Equatable {\n" +
    reasons.map(({ name, number }) => `  case ${swift(name)} = ${number}`).join("\n") +
    "\n\n  var branch: ReallyMeJOSEErrorBranch {\n    switch self {\n" +
    reasons.map(({ name }) => `    case .${swift(name)}: .${branch(name)}`).join("\n") +
    "\n    }\n  }\n\n  func validate(branch: ReallyMeJOSEErrorBranch) throws(ReallyMeJOSEError) {\n    guard self.branch == branch else { throw .malformedProviderResponse }\n  }\n}\n";
  const kotlin = header + "package me.really.jose\n\ninternal object JoseContractValues {\n" +
    `    const val NATIVE_ABI_VERSION: Int = ${abi[0].number}\n` +
    limits.map(({ name, number }) => `    const val ${name}: ${name.endsWith("SECONDS") ? "Long" : "Int"} = ${number}${name.endsWith("SECONDS") ? "L" : ""}`).join("\n") +
    "\n}\n\n/** Schema-derived stable reason codes without caller data. */\npublic enum class ReallyMeJoseErrorReason(public val code: Int, internal val branch: ReallyMeJoseErrorBranch) {\n" +
    reasons.map(({ name, number }) => `    ${name}(${number}, ReallyMeJoseErrorBranch.${branch(name).toUpperCase()}),`).join("\n") +
    "\n    ;\n    internal companion object {\n        private val byCode: Map<Int, ReallyMeJoseErrorReason> = entries.associateBy { it.code }\n        fun fromCode(code: Int): ReallyMeJoseErrorReason? = byCode[code]\n    }\n}\n";
  const families = [
    ["JoseErrorBranch", "JOSE_ERROR_BRANCH_", "ErrorBranch", "ErrorBranch"],
    ["JoseSignatureAlgorithm", "JOSE_SIGNATURE_ALGORITHM_", "SignatureAlgorithm", "SignatureAlgorithm"],
    ["JoseJweKeyManagementAlgorithm", "JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_", "JWEKeyManagementAlgorithm", "KeyManagementAlgorithm"],
    ["JoseJweContentEncryptionAlgorithm", "JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_", "JWEContentEncryptionAlgorithm", "ContentEncryptionAlgorithm"],
    ["JoseJweCompressionAlgorithm", "JOSE_JWE_COMPRESSION_ALGORITHM_", "JWECompressionAlgorithm", "CompressionAlgorithm"],
  ];
  let swiftAlgorithms = header + "import ReallyMeJOSEProto\n\n";
  let kotlinAlgorithms = header + "package me.really.jose\n\n";
  for (const [schemaName, prefix, swiftName, converter] of families) {
    const values = enumeration(schema, schemaName, prefix);
    const protoSwiftCase = (name) => camel(name).replace(/^(a\d+)gcm$/u, "$1Gcm").replace(/^(es\d+)k$/u, "$1K");
    const swiftCase = (name) => name === "EDDSA" ? "edDSA" : camel(name).replaceAll("ecdhEs", "ecdhES").replaceAll("gcm", "GCM");
    const kotlinCase = (name) => name === "EDDSA" ? "ED_DSA" : name.replace(/^(A\d+)GCM$/u, "$1_GCM");
    const sdkSwift = `ReallyMeJOSE${swiftName}`;
    const sdkKotlin = `ReallyMeJose${swiftName.replace("JWE", "Jwe")}`;
    swiftAlgorithms += `public enum ${sdkSwift}: Sendable, Equatable, CaseIterable {\n` + values.map(({ name }) => `  case ${swiftCase(name)}`).join("\n") +
      `\n\n  public init(contract: ReallyMeProto${schemaName}) throws(ReallyMeJOSEError) {\n    switch contract {\n` +
      values.map(({ name }) => `    case .${protoSwiftCase(name)}: self = .${swiftCase(name)}`).join("\n") +
      "\n    default: throw .jose(branch: .provider, reason: .providerUnsupported)\n    }\n  }\n}\n\n" +
      `func proto${converter}(\n  _ value: ${sdkSwift}\n) -> ReallyMeProto${schemaName} {\n  switch value {\n` +
      values.map(({ name }) => `  case .${swiftCase(name)}: .${protoSwiftCase(name)}`).join("\n") + "\n  }\n}\n\n";
    kotlinAlgorithms += `public enum class ${sdkKotlin} {\n` + values.map(({ name }) => `    ${kotlinCase(name)},`).join("\n") +
      `\n    ;\n    public companion object {\n        @JvmStatic\n        public fun fromContract(value: me.really.jose.v1.${schemaName}?): ${sdkKotlin} = when (value) {\n` +
      values.map(({ name }) => `            me.really.jose.v1.${schemaName}.${prefix}${name} -> ${kotlinCase(name)}`).join("\n") +
      "\n            else -> throw ReallyMeJoseException.JoseFailure(ReallyMeJoseErrorBranch.PROVIDER, ReallyMeJoseErrorReason.PROVIDER_UNSUPPORTED)\n        }\n    }\n}\n\n" +
      `internal fun proto${converter}(value: ${sdkKotlin}): me.really.jose.v1.${schemaName} = when (value) {\n` +
      values.map(({ name }) => `    ${sdkKotlin}.${kotlinCase(name)} -> me.really.jose.v1.${schemaName}.${prefix}${name}`).join("\n") + "\n}\n\n";
  }
  const tsGenerated = readFileSync(new URL("packages/ts/src/proto/generated/reallyme/jose/v1/jose_pb.ts", root), "utf8");
  const tsTypes = [...tsGenerated.matchAll(/^export type (\w+)/gmu)].map((value) => value[1]);
  const tsValues = [...tsGenerated.matchAll(/^export (?:const|enum) (\w+)/gmu)].map((value) => value[1]);
  const exports = header + `export {\n${tsValues.map((name) => `  ${name},`).join("\n")}\n} from "./proto/generated/reallyme/jose/v1/jose_pb.js";\n` +
    `export type {\n${tsTypes.map((name) => `  ${name},`).join("\n")}\n} from "./proto/generated/reallyme/jose/v1/jose_pb.js";\n`;
  const formattedRust = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], { input: rust, encoding: "utf8" });
  if (formattedRust.status !== 0) throw new TypeError("formatting schema-derived Rust values failed");
  const formattedFailures = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], { input: failureSource, encoding: "utf8" });
  if (formattedFailures.status !== 0) throw new TypeError("formatting schema-derived failure mappings failed");
  const files = new Map([
    ...nativeSelectors(schema, header),
    ...policyPresets(schema, header),
    ...sdkVerification(schema, header),
    ["crates/jose/src/map_failure.rs", formattedFailures.stdout],
    ["crates/proto/src/generated/package.rs", header + `/// Canonical protobuf package for ReallyMe JOSE boundary messages.\npub const JOSE_PROTO_PACKAGE: &str = "${packageName}";\n`],
    ["crates/proto/src/generated/contract_values.rs", formattedRust.stdout],
    ["packages/ts/src/proto/contract-values.ts", typescript],
    ["packages/swift/Sources/ReallyMeJOSE/ContractValues.swift", swiftSource],
    ["packages/kotlin/src/main/kotlin/me/really/jose/ContractValues.kt", kotlin],
    ["packages/swift/Sources/ReallyMeJOSE/ContractAlgorithms.swift", swiftAlgorithms.trimEnd() + "\n"],
    ["packages/kotlin/src/main/kotlin/me/really/jose/ContractAlgorithms.kt", kotlinAlgorithms.trimEnd() + "\n"],
    ["packages/ts/src/proto.ts", exports],
    ...swiftCleanup(schema, header),
  ]);
  for (const [relative, content] of files) {
    const path = fileURLToPath(new URL(relative, root));
    if (check) {
      if (readFileSync(path, "utf8") !== content) throw new TypeError("schema-derived contract values are stale");
    } else {
      mkdirSync(new URL(".", new URL(relative, root)), { recursive: true });
      writeFileSync(path, content);
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.slice(2).some((value) => value !== "--check")) throw new TypeError("unsupported generation argument");
  generateContractValues({ check: process.argv.includes("--check") });
}
