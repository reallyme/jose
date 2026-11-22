#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { checkProtobufContract } from "./check-protobuf-contract.mjs";
import { checkProtobufHardening } from "./check-protobuf-hardening.mjs";
import { assertOperationContractArchitecture } from "./operation-contract-readiness.mjs";
import { schemaMessages } from "./read-proto-schema.mjs";

const coreUrl = process.env.RELEASE_READINESS_CORE_URL;
if (typeof coreUrl !== "string" || coreUrl.length === 0) {
  console.error("release readiness check failed: pinned core URL is unavailable");
  process.exit(1);
}
const { createReleaseReadinessContext } = await import(coreUrl);

const {
  readText,
  readJson,
  listFiles,
  loadTrackedFiles,
  fail,
  assertContains,
  assertNotContains,
  assertNotMatches,
  assertLockPackageVersion,
  run,
  assertNodeWorkflowJobsPinNode,
  assertProtoContract,
  assertWorkflowRunStep,
  extractWorkflowSteps,
  assertReallyMeReleasePackagePolicy,
  assertReallyMeProtobufReleasePolicy,
  assertRustReleasePolicy,
  assertWorkflowActionsPinned,
  assertCargoFuzzWorkflowPolicy,
  assertWorkflowPermissionsPolicy,
  assertRustSourcePolicy,
  assertTypeScriptSourcePolicy,
  assertSwiftSourcePolicy,
  assertKotlinSourcePolicy,
  runNodeCheck,
} = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

const assertMarkdownContains = (path, needle) => {
  const normalize = (value) => value.replace(/\s+/gu, " ");
  if (!normalize(readText(path)).includes(normalize(needle))) {
    fail(`${path} is missing required usage or safety information: ${needle}`);
  }
};

const assertRawContains = (path, needle, description) => {
  if (!readText(path).includes(needle)) {
    fail(`${path} is missing ${description}`);
  }
};

assertReallyMeReleasePackagePolicy({ version: "0.9.9" });
assertWorkflowActionsPinned();
for (const [workflow, job] of [
  [".github/workflows/fuzz-ci.yml", "build"],
  [".github/workflows/fuzz.yml", "scheduled"],
]) {
  assertCargoFuzzWorkflowPolicy({
    workflow,
    versionFromWorkflowEnv: true,
    minimumInstallations: 1,
    requiredInstallSteps: [{ name: "Install cargo-fuzz", job }],
  });
}
assertOperationContractArchitecture({ readText, listFiles, fail });
checkProtobufContract();
checkProtobufHardening();
runNodeCheck("scripts/prepare_semver_baseline.test.mjs");
runNodeCheck("scripts/check-protobuf-contract.test.mjs");
runNodeCheck("scripts/check-protobuf-hardening.test.mjs");
runNodeCheck("scripts/generate-jose-proto.test.mjs");
runNodeCheck("scripts/generate-swift-cleanup.test.mjs");
runNodeCheck("scripts/maven_central_bundle.test.mjs");
runNodeCheck("scripts/release_crate_archives.test.mjs");

const crateVersion = "0.5.2";
const protoCrateVersion = crateVersion;
const buffaVersion = "0.1.3";
const cryptoVersion = "0.4.5";
const codecVersion = "0.4.5";
const npmPackageVersion = crateVersion;
run(process.execPath, ["scripts/verify_sdk_release_version.mjs", crateVersion]);
const rustSemverBaselineCommit = "cc7870f049eeef3ab09699797d2fa78b5c17dbcf";
const releaseReadinessCommit = "16aab5287de498e858ff3b85d9e66d7c9f7ebb74";
const releaseReadinessCommand = "node .release-readiness/scripts/run-consumer-check.mjs";
const releaseRust = "1.100.0";
const minimumRust = "1.100.0";
const rustWorkflow = ".github/workflows/rust-ci.yml";
const cargoDenyInstall = `cargo +${releaseRust} install cargo-deny --version '=0.22.0' --locked --force`;
const releaseRustTest = `cargo +${releaseRust} test --locked --workspace --all-features`;
const rustReleasePolicy = {
  release: { workflow: rustWorkflow, job: "rust", step: "Test on the release toolchain" },
  artifacts: [
    {
      workflow: ".github/workflows/swift-ci.yml",
      job: "swift",
      step: "Build runtime-loaded native library",
      run: `cargo +${releaseRust} build --locked -p reallyme-jose-ffi`,
    },
    {
      workflow: ".github/workflows/swift-package-preflight.yml",
      job: "swift-package",
      step: "Build JOSE FFI dylib",
      run: `cargo +${releaseRust} build --locked -p reallyme-jose-ffi`,
    },
  ],
  msrv: [
    { package: "reallyme-jose", workflow: rustWorkflow, job: "msrv", step: "Test JOSE at its declared MSRV" },
    { package: "reallyme-jose-proto", workflow: rustWorkflow, job: "msrv", step: "Test JOSE protobuf at its declared MSRV" },
  ],
  dependencyReview: { workflow: rustWorkflow, job: "rust", step: "Check locked dependencies" },
};
assertRustReleasePolicy(rustReleasePolicy);
const releaseReadinessCheckoutRequired = [
  "repository: reallyme/release-readiness",
  `ref: ${releaseReadinessCommit}`,
  "path: .release-readiness",
];
const generatedFreshnessMode = process.argv.includes("--generated-freshness");
const policyOnlyMode = process.argv.includes("--policy-only");
const releasePackagesMode = process.argv.includes("--release-packages");

// Policy-only jobs prove the shared structural rules without rerunning every
// platform-native suite. The default readiness job executes these commands on
// macOS, while the dedicated language workflows retain their own full matrix.
const sourceVerification = (commands) => {
  if (!policyOnlyMode) return commands;
  return [{
    roles: commands.flatMap((command) => command.roles),
    command: process.execPath,
    args: ["--version"],
  }];
};

if (releasePackagesMode && process.env.RELEASE_VERSION !== crateVersion) {
  fail(`RELEASE_VERSION must match every ${crateVersion} release package`);
}

assertNodeWorkflowJobsPinNode({ nodeVersion: "26" });

const rootCargo = readText("Cargo.toml");
const projectLicense = "MIT OR Apache-2.0";
assertContains("Cargo.toml", `license = "${projectLicense}"`);
for (const manifest of ["packages/ts/package.json", "tools/panva-goldens/package.json"]) {
  if (readJson(manifest).license !== projectLicense) fail(`${manifest} has stale project licensing`);
}
assertNotContains("LICENSE-MIT", "SPDX-License-Identifier:");
assertContains("LICENSE-MIT", "Permission is hereby granted, free of charge");
assertNotContains("LICENSE-APACHE", "SPDX-License-Identifier:");
assertContains("LICENSE-APACHE", "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION");
const packagedLicenseText = readText("crates/jose/LICENSE");
assertContains("crates/jose/LICENSE", "licensed under either the MIT");
assertContains("crates/jose/LICENSE", "Apache License, Version 2.0");
for (const copy of ["crates/jose/LICENSE", "crates/proto/LICENSE", "crates/wasm/LICENSE", "packages/ts/LICENSE"]) {
  if (readText(copy) !== packagedLicenseText) fail(`${copy} differs from the packaged dual license`);
}
for (const build of ["packages/kotlin/build.gradle.kts", "packages/kotlin-android/build.gradle.kts"]) {
  assertContains(build, 'name.set("MIT License")');
  assertContains(build, 'name.set("Apache License, Version 2.0")');
  assertContains(build, "Licensed under MIT OR Apache-2.0, at your option.");
}

assertContains("Cargo.toml", 'members = ["crates/jose", "crates/ffi", "crates/proto", "crates/wasm"]');
assertContains("Cargo.toml", 'exclude = ["fuzz"]');
assertContains("Cargo.toml", "overflow-checks = true");
assertContains("crates/wasm/Cargo.toml", "wasm-opt = false");
assertContains("Cargo.toml", "[profile.release-ffi]");
assertContains("Cargo.toml", 'inherits = "release"');
assertContains("Cargo.toml", 'panic = "unwind"');
assertContains("Cargo.toml", `buffa = { package = "reallyme-buffa", version = "=${buffaVersion}", features = ["json", "zeroize"] }`);
assertContains("Cargo.toml", 'missing_docs = "deny"');
for (const lint of [
  'arithmetic_side_effects = "deny"',
  'as_conversions = "deny"',
  'indexing_slicing = "deny"',
  'missing_const_for_fn = "deny"',
  'must_use_candidate = "deny"',
]) {
  assertContains("Cargo.toml", lint);
}
assertContains(
  "Cargo.toml",
  `reallyme-codec = { version = "=${codecVersion}", default-features = false }`,
);
assertContains(
  "Cargo.toml",
  `reallyme-jose-proto = { version = "${protoCrateVersion}", path = "crates/proto", default-features = false }`,
);
assertContains(
  "Cargo.toml",
  `reallyme-crypto = { version = "${cryptoVersion}", default-features = false }`,
);
assertContains(
  "fuzz/Cargo.toml",
  `reallyme-crypto = { version = "${cryptoVersion}", default-features = false, features = ["jwk"] }`,
);
assertNotContains("Cargo.toml", "reallyme-codec = { path");
assertNotContains("Cargo.toml", "reallyme-crypto = { path");
assertNotContains("fuzz/Cargo.toml", "reallyme-crypto = { path");
assertNotContains("Cargo.toml", 'time = "');

const ffiCargo = readText("crates/ffi/Cargo.toml");
assertContains("crates/ffi/Cargo.toml", 'name = "reallyme-jose-ffi"');
assertContains("crates/ffi/Cargo.toml", `version = "${crateVersion}"`);
assertContains("crates/ffi/Cargo.toml", "publish = false");
assertContains("crates/ffi/Cargo.toml", 'crate-type = ["rlib", "staticlib", "cdylib"]');
assertContains("crates/ffi/Cargo.toml", 'default = ["native"]');
assertContains("crates/ffi/Cargo.toml", `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`);
assertContains(
  "crates/ffi/Cargo.toml",
  'native = ["reallyme-crypto/native", "reallyme-jose/native"]',
);
assertContains("crates/ffi/Cargo.toml", 'features = ["csprng"]');
assertContains(
  "crates/ffi/Cargo.toml",
  `reallyme-jose = { version = "${crateVersion}", path = "../jose", default-features = false, features = ["wire"] }`,
);
assertContains("crates/ffi/Cargo.toml", "workspace = true");
assertNotContains("crates/ffi/Cargo.toml", "publish = true");
if (ffiCargo.includes("swift") || ffiCargo.includes("kotlin")) {
  fail("crates/ffi/Cargo.toml must keep platform provider selection outside Rust features");
}

const crateCargo = readText("crates/jose/Cargo.toml");
assertContains("crates/jose/Cargo.toml", 'name = "reallyme-jose"');
assertContains("crates/jose/Cargo.toml", `version = "${crateVersion}"`);
assertContains(
  "crates/jose/Cargo.toml",
  'description = "JOSE, JWT, JWS, and JWE helpers for ReallyMe identity."',
);
assertContains("crates/jose/Cargo.toml", "publish = true");
assertContains("crates/jose/Cargo.toml", "[package.metadata.cargo_check_external_types]");
for (const externalType of [
  '"crypto_core::algorithm::Algorithm"',
  '"crypto_csprng::rng::SecureRandom"',
  '"envelopes_jwk::jwk::Jwk"',
  '"reallyme_crypto_proto::error_types::CryptoError"',
  '"reallyme_jose_proto::*"',
  '"serde_core::de::DeserializeOwned"',
  '"zeroize::Zeroizing"',
]) {
  assertContains("crates/jose/Cargo.toml", externalType);
}
assertContains("crates/jose/Cargo.toml", 'documentation = "https://docs.rs/reallyme-jose"');
assertContains("crates/jose/Cargo.toml", 'categories = ["authentication", "cryptography", "encoding"]');
assertContains("crates/jose/Cargo.toml", 'keywords = ["jose", "jwt", "jws", "jwe", "reallyme"]');
assertContains(
  "crates/jose/Cargo.toml",
  'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
);
assertContains(
  "crates/jose/Cargo.toml",
  'reallyme-codec = { workspace = true, features = ["base64", "base64url"] }',
);
assertContains("crates/jose/Cargo.toml", "reallyme-crypto = { workspace = true }");
assertContains("Cargo.toml", 'flate2 = { version = "1.1.11", default-features = false, features = ["rust_backend"] }');
assertContains("crates/jose/Cargo.toml", "flate2 = { workspace = true }");
assertContains(
  "crates/jose/Cargo.toml",
  'reallyme-jose-proto = { workspace = true, features = ["generated"], optional = true }',
);
assertContains("crates/jose/Cargo.toml", 'wire = ["dep:buffa", "dep:reallyme-jose-proto"]');
assertContains("crates/jose/Cargo.toml", "buffa = { workspace = true, optional = true }");
assertNotContains("crates/jose/Cargo.toml", "reallyme-codec = { path");
assertNotContains("crates/jose/Cargo.toml", "reallyme-crypto = { path");
assertNotContains("crates/jose/Cargo.toml", "time = { workspace = true }");

assertContains("crates/proto/Cargo.toml", 'name = "reallyme-jose-proto"');
assertContains("crates/proto/Cargo.toml", `version = "${protoCrateVersion}"`);
assertContains(
  "crates/proto/Cargo.toml",
  'description = "ReallyMe JOSE protobuf boundary messages generated with Buffa."',
);
assertContains(
  "crates/proto/Cargo.toml",
  'categories = ["authentication", "cryptography", "encoding"]',
);
assertContains("crates/proto/Cargo.toml", 'keywords = ["jose", "jwt", "jws", "jwe", "reallyme"]');
assertContains("crates/proto/Cargo.toml", "publish = true");
assertContains("crates/proto/Cargo.toml", 'generated = ["dep:base64", "dep:buffa", "buffa/json", "dep:serde", "dep:zeroize", "dep:secrecy", "dep:subtle"]');
assertContains("crates/proto/Cargo.toml", 'default = ["generated"]');
assertContains(
  "crates/proto/Cargo.toml",
  'documentation = "https://docs.rs/reallyme-jose-proto"',
);
assertContains("crates/proto/Cargo.toml", "[package.metadata.docs.rs]");
assertContains("crates/proto/Cargo.toml", "all-features = true");
assertContains("crates/proto/Cargo.toml", '"/tests/**/*.rs"');
assertContains("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
assertMarkdownContains(
  "crates/proto/README.md",
  `reallyme-jose-proto = { version = "${protoCrateVersion}", features = ["generated"] }`,
);
assertMarkdownContains("crates/proto/README.md", "JoseOperationRequest");
assertMarkdownContains("crates/proto/README.md", "JoseOperationResponse");
assertMarkdownContains("crates/proto/README.md", "operation-discriminated response");
assertMarkdownContains("crates/proto/README.md", "Copyright © 2026 by ReallyMe Technologies Limited.");
assertContains("crates/proto/NOTICE", "ReallyMe JOSE Proto");
assertContains(
  "crates/proto/src/generated/package.rs",
  'pub const JOSE_PROTO_PACKAGE: &str = "reallyme.jose.v1";',
);

const wasmCargo = readText("crates/wasm/Cargo.toml");
assertContains("crates/wasm/Cargo.toml", 'name = "reallyme-jose-wasm"');
assertContains("crates/wasm/Cargo.toml", `version = "${npmPackageVersion}"`);
assertContains("crates/wasm/Cargo.toml", "publish = false");
assertContains("crates/wasm/Cargo.toml", 'crate-type = ["cdylib", "rlib"]');
assertContains("crates/wasm/Cargo.toml", 'features = ["wasm", "wire"]');
assertContains("crates/wasm/Cargo.toml", "workspace = true");
assertNotContains("crates/wasm/Cargo.toml", "publish = true");
assertNotContains("crates/wasm/Cargo.toml", 'features = ["swift"');
assertNotContains("crates/wasm/Cargo.toml", 'features = ["kotlin"');
assertContains("crates/wasm/src/operation.rs", "execute_operation_v1");
assertContains("crates/wasm/src/operation.rs", "execute_operation_json_v1");
assertContains("crates/wasm/src/operation.rs", "Zeroizing<Vec<u8>>");
assertNotContains("crates/wasm/src/operation.rs", "processProto");
if (!wasmCargo.includes('reallyme-crypto = { workspace = true, features = ["csprng", "wasm"] }')) {
  fail("WASM adapter must use the reviewed ReallyMe Crypto CSPRNG WASM lane");
}

const npmPackage = readJson("packages/ts/package.json");
if (npmPackage.name !== "@reallyme/jose" || npmPackage.version !== npmPackageVersion) {
  fail("TypeScript package identity or version is not release-aligned");
}
if (npmPackage.publishConfig?.registry !== "https://registry.npmjs.org/") {
  fail("TypeScript package registry must be the public npm registry");
}
assertContains("packages/ts/package.json", '"@bufbuild/protobuf": "2.17.0"');
assertContains("packages/ts/package-lock.json", '"name": "@reallyme/jose"');
assertContains("packages/ts/package-lock.json", `"version": "${npmPackageVersion}"`);
assertContains("packages/ts/tsconfig.json", '"strict": true');
assertContains("packages/ts/tsconfig.json", '"noUnusedLocals": true');
assertContains("packages/ts/tsconfig.json", '"noUnusedParameters": true');
assertMarkdownContains("packages/ts/README.md", "## Raw WASM Module Contract");
assertMarkdownContains("packages/ts/README.md", "Direct raw WASM calls are unsupported");
assertContains("packages/ts/src/errors.ts", "class ReallyMeJoseError extends Error");
assertContains("packages/ts/src/provider.ts", "installReallyMeJoseWasmProvider");
assertContains("packages/ts/src/facade.ts", "export const ReallyMeJose = Object.freeze");
assertContains("packages/ts/src/facade-support.ts", "outcome.value.protectedHeaderJson.fill(0)");
assertContains("packages/ts/src/facade-support.ts", "outcome.value.payload.fill(0)");
assertContains("packages/ts/scripts/build-wasm.mjs", 'const REQUIRED_WASM_PACK_VERSION = "0.15.1"');
assertContains("packages/ts/scripts/build-wasm.mjs", 'const REQUIRED_WASM_BINDGEN_VERSION = "0.2.130"');
assertContains("packages/ts/scripts/check-pack.mjs", "unreviewed semantic export");
assertContains("packages/ts/test/vector-conformance.test.mjs", "all 104 cross-lane conformance vectors");
assertContains("packages/ts/test/vector-conformance.test.mjs", "PROVIDER_UNSUPPORTED");
assertContains("scripts/verify_sdk_release_version.mjs", '"crates/wasm/Cargo.toml"');
assertContains("scripts/verify_sdk_release_version.mjs", '"packages/ts/package.json"');
for (const forbidden of ["@ts-ignore", ": any", "Result<string", "processProto"]) {
  for (const sourceFile of [
    "packages/ts/src/boundary.ts",
    "packages/ts/src/errors.ts",
    "packages/ts/src/facade.ts",
    "packages/ts/src/memory.ts",
    "packages/ts/src/provider.ts",
    "packages/ts/src/validate.ts",
    "packages/ts/src/wasmModuleTypes.ts",
  ]) {
    assertNotContains(sourceFile, forbidden);
  }
}

assertContains("crates/jose/src/lib.rs", "csprng::{OsSecureRandom, SecureRandom}");
assertContains("crates/jose/src/lib.rs", "pub use serde_json::Value as JsonValue;");
assertContains("crates/jose/src/lib.rs", "pub use zeroize::Zeroizing;");
assertContains(
  "crates/jose/src/lib.rs",
  '#[cfg(any(feature = "native", feature = "wasm"))]\nmod operation_contract;',
);
assertContains("crates/jose/src/lib.rs", "pub mod wire;");
assertContains("crates/jose/src/lib.rs", '#[cfg(all(any(feature = "native", feature = "wasm"), feature = "wire"))]');
for (const file of [
  "crates/jose/src/jwe/error.rs",
  "crates/jose/src/generated_contract/jwe_key_management_algorithm.rs",
  "crates/jose/src/generated_contract/jwe_content_encryption_algorithm.rs",
  "crates/jose/src/generated_contract/jwe_compression_algorithm.rs",
  "crates/jose/src/jwt/error.rs",
  "crates/jose/src/jws/suites/es256.rs",
  "crates/jose/src/jws/suites/eddsa.rs",
  "crates/jose/src/wire.rs",
]) {
  assertContains(file, "#[non_exhaustive]");
}
assertContains("crates/jose/src/jwt/mod.rs", "decode_unsigned_jwt_claims_json");
assertContains("crates/jose/src/jwt/mod.rs", "mod strict_json;");
assertContains("crates/jose/src/jwt/strict_json.rs", "reject_duplicate_object_members");
assertContains(
  "crates/jose/src/reject_duplicate_json_members.rs",
  "pub(crate) fn reject_duplicate_json_members",
);
assertContains(
  "crates/jose/src/jwt/mod.rs",
  "decode_verify_jwt_claims_json_signature_only_with_header_validation",
);
assertContains("crates/jose/src/jwt/verify.rs", "const ED25519_SIGNATURE_LEN: usize = crate::resolve_algorithm::JwtAlgorithm::Eddsa.signature_len();");
assertContains(
  "crates/jose/src/jws/parse_compact.rs",
  "Result<Zeroizing<Vec<u8>>, E>",
);
assertContains(
  "crates/jose/src/jwe/derive_key.rs",
  "let bytes = Zeroizing::new(match value",
);
assertContains("crates/jose/src/jwe/derive_key.rs", "JweError::InvalidSharedSecret");
assertContains("crates/jose/src/jwe/derive_key.rs", "JweError::KeyDerivation");
assertContains("crates/jose/src/jwe/validate_header.rs", "struct PublicEpkJwk");
assertContains(
  "crates/jose/src/jwe/validate_header.rs",
  "impl<'de> Deserialize<'de> for CompactJweProtectedHeader",
);
assertContains(
  "crates/jose/src/jwe/validate_header.rs",
  "validate_jwe_header_structure(",
);
assertContains(
  "crates/jose/src/generated_contract/jwe_compression_algorithm.rs",
  "pub enum JweCompressionAlgorithm",
);
assertContains("crates/jose/src/generated_contract/jwe_compression_algorithm.rs", 'Self::Deflate => "DEF"');
assertContains("crates/jose/src/jwe/compression.rs", "reallyme_jose_proto::generated::contract_values::COMPACT_BYTES;");
assertContains("crates/jose/src/jwe/compression.rs", "DeflateEncoder::new");
assertContains("crates/jose/src/jwe/compression.rs", "DeflateDecoder::new");
assertContains("crates/jose/src/jwe/compression.rs", "Zeroizing<Vec<u8>>");
const jweDecryptPath = "crates/jose/src/jwe/decrypt.rs";
assertContains(jweDecryptPath, "finish_decryption(\n        decrypt_content(");
assertContains(jweDecryptPath, "|plaintext| decompress_deflate(&plaintext)");
assertContains(jweDecryptPath, "let plaintext = authenticated?;");
assertContains(jweDecryptPath, "Some(JweCompressionAlgorithm::Deflate) => decompress(plaintext)");
const jweDecryptSource = readText(jweDecryptPath);
if (jweDecryptSource.indexOf("let plaintext = authenticated?;") >= jweDecryptSource.indexOf("=> decompress(plaintext)")) {
  fail("compact-JWE decryption must authenticate AES-GCM before inflating plaintext");
}
assertContains("crates/jose/tests/jwe_tests/cases.rs", "deflate_is_serialized_and_applied_before_each_gcm_cipher");
assertContains("crates/jose/tests/jwe_tests/cases.rs", "deflate_requires_explicit_decryption_policy");
assertContains(
  "crates/jose/tests/jwe_tests/support_and_boundaries.rs",
  "authenticated_deflate_is_bounded_against_decompression_bombs",
);
assertContains(
  "crates/jose/tests/jwe_tests/support_and_boundaries.rs",
  "authenticated_invalid_deflate_is_rejected_after_authentication",
);
assertContains(
  "crates/jose/tests/jwe_tests/negative_cases.rs",
  "rejects_tampered_deflate_before_decoding_for_each_gcm_suite",
);
assertContains("crates/jose/src/wire.rs", "reject_duplicate_json_members(bytes)");
assertContains(
  "crates/jose/src/operation_contract/protobuf/jwt.rs",
  "JoseJwtClaimsResult",
);
assertNotContains("crates/jose/src/wire.rs", "fn encode_claims_result(");
assertNotContains("crates/jose/src/wire.rs", "fn map_jwt_error(");
assertNotContains("crates/jose/src/wire.rs", "serde_json::to_vec(&claims)");
assertNotContains(
  "crates/jose/src/operation_contract/jws/mod.rs",
  "mod differential_tests;",
);
assertNotContains("crates/jose/src/lib.rs", "mod codec;");
assertNotContains("crates/jose/src/jws/sign.rs", "JwsSigningInputError::Codec");
assertNotContains("crates/jose/src/jws/sign.rs", "encode_base64url");
assertNotContains("crates/jose/src/jws/suites/es256.rs", "EncodingFailed");
assertNotContains("crates/jose/src/jws/suites/eddsa.rs", "EncodingFailed");
assertNotContains("crates/jose/src/jwe/error.rs", "EncodingFailed");
assertNotContains("crates/jose/src/jwe/encrypt.rs", "encode_base64url");
assertNotContains("crates/jose/src/jwe/validate_header.rs", "encode_base64url");
assertNotContains("crates/jose/src/jwt/sign.rs", "encode_base64url");
assertNotContains("crates/jose/src/jwt/unsigned.rs", "encode_base64url");
assertNotContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JWS_ENCODING_FAILED");
assertNotContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JWE_ENCODING_FAILED");
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8 = 103;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64 = 104;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED = 703;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_KEY_DERIVATION_FAILED = 902;",
);
assertRawContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "Shared identity; compact JWS accepts only EdDSA and ES256.",
  "the shared signature identity and profile restriction",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "reserved 1 to 3;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_SIGNATURE_ALGORITHM_ES256K = 230;");
assertNotContains("crates/jose/src/wire.rs", "JOSE_SIGNATURE_ALGORITHM_ES256K");
assertNotContains("crates/jose/src/lib.rs", "#![allow(missing_docs)]");

const lock = readText("Cargo.lock");
const cratesIo = "registry+https://github.com/rust-lang/crates.io-index";
const fuzzLock = readText("fuzz/Cargo.lock");
for (const dependencyLock of [lock, fuzzLock]) {
  for (const name of ["reallyme-codec", "reallyme-codec-base64", "reallyme-codec-base64url"]) {
    assertLockPackageVersion(dependencyLock, name, codecVersion, cratesIo);
  }
  // Check every locked occurrence so an older transitive release cannot hide
  // beside a correctly pinned direct dependency.
  for (const entry of dependencyLock.split("[[package]]").slice(1)) {
    const match = /^name = "(reallyme-(codec|crypto)(?:-[a-z0-9-]+)?)"$/mu.exec(entry);
    if (match !== null) {
      const [, name, family] = match;
      const version = family === "codec" ? codecVersion : cryptoVersion;
      assertLockPackageVersion(`[[package]]${entry}`, name, version, cratesIo);
    }
  }
  assertLockPackageVersion(dependencyLock, "reallyme-crypto", cryptoVersion, cratesIo);
  assertLockPackageVersion(dependencyLock, "reallyme-crypto-proto", cryptoVersion, cratesIo);
}
assertLockPackageVersion(lock, "reallyme-jose-proto", protoCrateVersion);

assertContains("README.md", "actions/workflows/ci.yml/badge.svg");
assertContains("README.md", "crates.io/crates/reallyme-jose");
assertContains("README.md", "central.sonatype.com/artifact/me.really/jose");
assertContains("README.md", "img.shields.io/npm/v/@reallyme/jose");
assertContains("README.md", "npmjs.com/package/@reallyme/jose");
assertContains("README.md", `npm install @reallyme/jose@${npmPackageVersion}`);
assertContains("README.md", `reallyme-jose = "${crateVersion}"`);
assertContains("README.md", "RSA JWS and RSA JWE algorithms");
assertContains("README.md", "JWT signing and verification for `ES256`, `ES256K`, and `EdDSA`");
assertContains("README.md", "## Crates");
assertContains("README.md", "publishes two Rust crates");
assertContains("README.md", "## Wire Boundary");
assertContains("README.md", "reallyme-jose-proto");
assertContains("README.md", "Both supported runtime lanes include the generated");
assertContains("README.md", "Owned wire output buffers use `Zeroizing<Vec<u8>>`");
assertContains("README.md", "Decode `JoseOperationResponse`");
assertContains("README.md", "only executable wire surface");
assertContains("README.md", "`api::execute` executes generated requests");
assertContains("README.md", "Native and generated APIs share semantic implementations");
assertContains("README.md", "does not define an RPC service, transport, endpoint");
assertContains("README.md", "a new minor release may intentionally change the schema");
assertContains("README.md", "Unsigned JWT decoding is parsing only");
assertContains("README.md", "JWT wire header policy is presence-sensitive");
assertContains("README.md", "JWT verification requires one `verification.mode`");
assertContains("README.md", "JWE decrypt requests can carry a presence-sensitive protected-header policy");
assertContains("README.md", "Time-validating modes require a valid current time");
assertContains("README.md", "also rejects any message whose protobuf encoding");
assertContains("README.md", "The policy lane also runs for documentation-only changes");
assertContains("README.md", "Independent Vector Audit");
assertContains("README.md", "ES256 verification accepts both low-S and high-S ECDSA signatures");
assertContains("README.md", "Face ID and Secure");
assertContains("README.md", "challenge, nonce, `jti`, payload");
assertContains("README.md", "Those deserialized values are not zeroizing owners");
assertContains("README.md", "wasm feature lane uses package-owned Rust cryptographic implementations");
assertContains("README.md", "raw DEFLATE format before AES-GCM encryption");
assertContains("README.md", "zip_values_supported: [\"DEF\"]");
assertContains("README.md", "decompressed-plaintext ceiling");
assertMarkdownContains("SECURITY.md", "AES-GCM tag before any inflate work");
assertMarkdownContains("SECURITY.md", "compression side channel");
assertMarkdownContains("crates/jose/README.md", "## Operation Execution Boundary");
assertMarkdownContains("crates/jose/README.md", "Owned wire outputs use zeroizing buffers");
assertMarkdownContains("crates/jose/README.md", "Keep `reallyme-jose-proto` on the same release");
assertMarkdownContains("crates/jose/README.md", "does not authenticate the sender");
assertMarkdownContains("crates/jose/README.md", "types included by both runtime lanes");
assertMarkdownContains("crates/jose/README.md", "`api::contract` re-exports the generated types");
assertMarkdownContains("crates/jose/README.md", "response contract V2");
assertMarkdownContains("crates/jose/README.md", "execute_operation_json_v1");
assertMarkdownContains("crates/jose/README.md", "`wire::execute_operation_v1` accepts binary protobuf");
assertMarkdownContains("crates/jose/README.md", "verified claims JSON reject duplicate members");
assertMarkdownContains("crates/jose/README.md", "accepts otherwise valid high-S signatures");
assertMarkdownContains("crates/jose/README.md", "issuer-controlled identifiers");
assertMarkdownContains("crates/jose/README.md", "zeroize on drop");
assertMarkdownContains("crates/jose/README.md", "wasm lane uses package-owned Rust cryptographic implementations");
assertMarkdownContains("crates/jose/README.md", "JWT wire header policy is presence-sensitive");
assertMarkdownContains("crates/jose/README.md", "Time-validating modes require a valid current time and bounded skew.");
assertMarkdownContains("crates/jose/README.md", "JWE decrypt policy can require `kid`");
assertMarkdownContains("crates/jose/README.md", "use binary protobuf for large byte payloads.");
assertMarkdownContains("crates/jose/README.md", "Raw DEFLATE runs before encryption");
assertMarkdownContains("crates/jose/README.md", "zip_values_supported: [\"DEF\"]");
assertMarkdownContains("crates/proto/README.md", "defines messages only");
assertMarkdownContains("crates/proto/README.md", "provides no RPC service or transport");
assertMarkdownContains("crates/proto/README.md", "Select one operation in the `JoseOperationRequest` oneof.");
assertMarkdownContains("crates/proto/README.md", "Require contract version V2");
assertMarkdownContains("crates/proto/README.md", "Responses are binary protobuf for both request encodings.");
assertMarkdownContains("crates/proto/README.md", "JWE decrypt requests include a presence-sensitive");
assertMarkdownContains("crates/proto/README.md", "Earlier wire semantics are unsupported.");
for (const readme of ["README.md", "crates/jose/README.md", "vectors/README.md", "fuzz/README.md"]) {
  assertContains(readme, "Copyright © 2026 by ReallyMe Technologies Limited.");
  assertContains(readme, "ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.");
}
assertContains("README.md", "[MIT License](LICENSE-MIT)");
assertContains("README.md", "[Apache License, Version 2.0](LICENSE-APACHE)");
assertMarkdownContains("crates/jose/README.md", "See [LICENSE](LICENSE) and");
assertMarkdownContains("crates/jose/README.md", "[NOTICE](NOTICE).");
assertMarkdownContains("vectors/README.md", "[MIT License](../LICENSE-MIT)");
assertMarkdownContains("vectors/README.md", "[Apache License, Version 2.0](../LICENSE-APACHE)");
assertMarkdownContains("vectors/README.md", "[NOTICE](../NOTICE).");
assertMarkdownContains("fuzz/README.md", "[MIT License](../LICENSE-MIT)");
assertMarkdownContains("fuzz/README.md", "[Apache License, Version 2.0](../LICENSE-APACHE)");
assertMarkdownContains("fuzz/README.md", "[NOTICE](../NOTICE).");
assertContains("vectors/manifest.json", "reallyme.jose.conformance.vector_manifest.v1");
assertContains("vectors/manifest.json", '"id": "panva-jose"');
assertContains("vectors/manifest.json", '"case_count": 4');
assertContains("vectors/panva-jose.json", '"suite": "panva-jose"');
assertContains("vectors/panva-jose.json", '"source": "panva/jose@6.2.18"');
assertContains("vectors/panva-jose.json", "panva-jose/jwe-ecdh-es-p256-a128gcm");
assertContains("vectors/panva-jose.json", "not a full algorithm matrix");
assertContains("vectors/panva-jose.json", "deterministic low scalars");
assertMarkdownContains("vectors/README.md", "`tools/panva-goldens`");
assertMarkdownContains("vectors/README.md", "`panva-jose.json` records the source library version.");
assertMarkdownContains("vectors/README.md", "schema-operations.json");
assertMarkdownContains("vectors/README.md", "expected V2 response bytes");
assertMarkdownContains("vectors/README.md", "P-256/A128GCM ECDH-ES");
assertMarkdownContains("vectors/README.md", "panva/WebCrypto does not provide");
assertMarkdownContains("vectors/README.md", "secp256k1 JOSE signing support");
assertMarkdownContains("vectors/README.md", "ES256 fixtures include valid high-S signatures");
assertMarkdownContains("vectors/README.md", "Fixture keys use deterministic low scalars and must never be used in production.");
assertContains("vectors/signed-jwt.json", "reallyme-jwt/kid-mismatch");
assertContains("README.md", "small native and WASM interop anchor");
assertContains("tools/panva-goldens/package.json", '"jose": "6.2.18"');
assertContains("tools/panva-goldens/package-lock.json", '"version": "6.2.18"');
assertContains("tools/panva-goldens/generate.mjs", "setKeyManagementParameters");
assertContains("tools/vector-audit/Cargo.toml", 'name = "reallyme-jose-vector-audit"');
assertContains("tools/vector-audit/src/main.rs", "PANVA_FILE");
assertContains("crates/jose/tests/panva_vectors.rs", "panva_jose_vectors_interoperate");
assertContains(
  ".github/workflows/crates-release.yml",
  "Publish reallyme-jose",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo nextest run --locked --workspace --all-features",
);
assertContains(".github/workflows/crates-package-preflight.yml", "cargo deny check");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  `ref: ${rustSemverBaselineCommit}`,
);
assertContains(
  "scripts/prepare_semver_baseline.mjs",
  `RUST_SEMVER_BASELINE_COMMIT = "${rustSemverBaselineCommit}"`,
);
assertContains("scripts/prepare_semver_baseline.mjs", 'resolve(root, "crates/jose/Cargo.toml")');
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo install cargo-semver-checks --version \"$CARGO_SEMVER_CHECKS_VERSION\" --locked",
);
assertContains(".github/workflows/crates-package-preflight.yml", "cargo semver-checks --workspace");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "--exclude reallyme-jose-ffi",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  `${releaseReadinessCommand} --policy-only`,
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "run: node scripts/publish_crates_in_order.mjs order",
);
assertContains(".github/workflows/crates-release.yml", "scripts/release_crate_archives.mjs publish");
assertContains(".github/workflows/crates-package-preflight.yml", "scripts/release_crate_archives.mjs seal");
assertNotContains(".github/workflows/crates-release.yml", "cargo publish");
assertNotContains(".github/workflows/crates-release.yml", "git tag");
assertNotContains(".github/workflows/crates-release.yml", "gh release create");
assertNotContains(".github/workflows/crates-release.yml", "contents: write");
assertContains(".github/workflows/crates-release.yml", "Summarize crates.io publication");
assertContains(".github/workflows/crates-release.yml", "node-version: '26'");
const cratesReleaseSource = readText(".github/workflows/crates-release.yml");
const credentialedCratesPublish = cratesReleaseSource.slice(
  cratesReleaseSource.indexOf("\n  publish:\n"),
);
if (credentialedCratesPublish.includes("Swatinem/rust-cache")) {
  fail("credentialed crates.io publication must not restore a shared Cargo cache");
}
assertWorkflowPermissionsPolicy({
  path: ".github/workflows/crates-release.yml",
  workflow: { contents: "read" },
  jobs: {
    "verify-release-sha": { actions: "read", contents: "read" },
    publish: { actions: "read", contents: "read" },
  },
});
assertContains("scripts/publish_crates_in_order.mjs", "cargo\", [\"metadata\"");
assertContains("scripts/publish_crates_in_order.mjs", "\"--locked\", \"--format-version\"");
assertContains("scripts/publish_crates_in_order.mjs", "checkPathDependencyVersions");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  'const REQUIRED_PUBLISH_ORDER_EDGES = [["reallyme-jose-proto", "reallyme-jose"]];',
);
assertContains("scripts/publish_crates_in_order.mjs", "checkRequiredPublishOrderEdges");
assertNotContains("scripts/publish_crates_in_order.mjs", 'const PACKAGE = "reallyme-jose"');
assertMarkdownContains("SECURITY.md", "security@really.me");
assertNotContains("SECURITY.md", "Report a vulnerability");
assertMarkdownContains("SECURITY.md", "Do not open a public issue");
assertContains("NOTICE", "ReallyMe JOSE");
assertNotContains("NOTICE", "ReallyMe Crypto");
assertNotContains("NOTICE", "BouncyCastle");
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: crates/proto/proto");
assertContains("buf.gen.yaml", "out: crates/proto/src/generated/buffa");
assertContains("buf.gen.yaml", "protoc-gen-reallyme-buffa-packaging");
assertContains("buf.gen.yaml", "buf.build/apple/swift:v1.39.0");
assertContains("buf.gen.yaml", "out: gen/swift");
assertContains("buf.gen.yaml", "Visibility=Public");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/java:v36.2");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/kotlin:v36.2");
assertContains("buf.gen.yaml", "out: gen/java");
assertContains("buf.gen.yaml", "out: gen/kotlin");
assertContains("buf.gen.yaml", "buf.build/bufbuild/es:v2.17.0");
assertContains("buf.gen.yaml", "out: packages/ts/src/proto/generated");
assertContains(".gitignore", "!crates/proto/src/generated/");
assertContains(".gitignore", "!crates/proto/src/generated/**");
assertContains(".github/workflows/protobuf-ci.yml", `BUFFA_VERSION: ${buffaVersion}`);
assertContains(".github/workflows/protobuf-ci.yml", "buf breaking --against");
assertContains("buf.gen.yaml", "clean: true");
assertContains(".github/workflows/crates-package-preflight.yml", "node scripts/generate-jose-proto.mjs");
for (const needle of releaseReadinessCheckoutRequired) {
  assertContains(".github/workflows/protobuf-ci.yml", needle);
  assertContains(".github/workflows/android-ci.yml", needle);
  assertContains(".github/workflows/readiness.yml", needle);
}
assertContains(
  ".github/workflows/protobuf-ci.yml",
  `${releaseReadinessCommand} --generated-freshness --policy-only`,
);
assertContains(".github/workflows/readiness.yml", releaseReadinessCommand);
assertContains(".github/workflows/readiness.yml", "runs-on: macos-26");
assertContains(".github/workflows/readiness.yml", "WASM_BINDGEN_CLI_VERSION: 0.2.130");
assertContains(".github/workflows/readiness.yml", "WASM_PACK_VERSION: 0.15.1");
assertContains(
  ".github/workflows/readiness.yml",
  'tool: wasm-bindgen-cli@${{ env.WASM_BINDGEN_CLI_VERSION }}',
);
assertContains(
  ".github/workflows/readiness.yml",
  'tool: wasm-pack@${{ env.WASM_PACK_VERSION }}',
);
assertContains(
  "README.md",
  releaseReadinessCommand,
);
for (const workflow of listFiles(".github/workflows").filter((path) => /\.ya?ml$/u.test(path))) {
  const source = readText(workflow);
  for (const [, ref] of source.matchAll(/^[ \t]+repository: reallyme\/release-readiness[ \t]*\r?\n[ \t]+ref: ([^\r\n]+)/gmu)) {
    if (ref.trimEnd() !== releaseReadinessCommit) fail(`${workflow} uses a different release-readiness commit`);
  }
}
for (const retiredPath of [
  ".github/workflows/release-readiness-drift.yml",
  "scripts/release-readiness/core.mjs",
  "scripts/run_pinned_release_readiness.mjs",
  "scripts/verify_release_attestation.mjs",
  "scripts/verify_release_attestation.test.mjs",
]) {
  if (loadTrackedFiles().has(retiredPath)) {
    fail(`${retiredPath} must remain retired after adopting the published runner`);
  }
}
assertContains(".github/workflows/crates-package-preflight.yml", "node scripts/generate-jose-proto.mjs");
assertContains(".github/workflows/protobuf-ci.yml", "node-version: '26'");
for (const option of ["zeroize_in=.reallyme.jose.v1", "unknown_fields=false", "deny_unknown_json_fields=true",
  "json_policy_type=crate::SecretBytes", "json_policy_type=crate::SecretString"]) assertContains("buf.gen.yaml", option);
for (const file of ["secret_bytes", "secret_string"]) {
  assertContains(`crates/proto/src/${file}.rs`, "crate::guarded_decode::read(payload)");
  assertContains(`crates/proto/src/${file}.rs`, "SecretBox");
}
assertContains("scripts/generate-jose-proto.mjs", "requireGeneratorVersions");
assertContains("crates/proto/Cargo.toml", 'zeroize = { workspace = true, optional = true }');
const protobufWorkflow = ".github/workflows/protobuf-ci.yml";
const protobufWorkflowSource = readText(protobufWorkflow);
const protobufFirstPolicy = {
  contractPath: "crates/proto/README.md",
  schemaPaths: ["crates/proto/proto/reallyme/jose/v1/jose.proto"],
  verification: {
    workflow: protobufWorkflow,
    job: "protobuf",
    step: "Check release readiness generated freshness",
    run: `${releaseReadinessCommand} --generated-freshness --policy-only`,
  },
  sdkConformance: {
    sharedFixtures: [
      "vectors/jws-compact.json",
      "vectors/jwe-compact.json",
      "vectors/signed-jwt.json",
      "vectors/unsigned-jwt.json",
      "vectors/panva-jose.json",
      "vectors/schema-operations.json",
    ],
    lanes: [
      {
        sdk: "swift",
        workflow: ".github/workflows/swift-ci.yml",
        job: "swift",
        step: "Test linked Swift XCFramework",
        run: "swift test",
      },
      {
        sdk: "typescript-wasm",
        workflow: rustWorkflow,
        job: "rust",
        step: "Test TypeScript package and WASM provider",
        run: "npm --prefix packages/ts test",
      },
      {
        sdk: "kotlin-jni",
        workflow: ".github/workflows/kotlin-ci.yml",
        job: "kotlin-jvm",
        step: "Test typed JVM facade and native JAR",
        run: "packages/kotlin/gradlew -p packages/kotlin --no-daemon test verifyJarContainsNativeResources",
      },
      {
        sdk: "android",
        workflow: ".github/workflows/android-ci.yml",
        job: "runtime",
        step: "Test minified Android consumer runtime",
        run: "bash -e -o pipefail scripts/run-android-emulator.sh",
      },
    ],
  },
};
for (const [name, version] of [["BUF_VERSION", "1.75.0"], ["BUFFA_VERSION", buffaVersion]]) {
  const declarations = [...protobufWorkflowSource.matchAll(new RegExp(`^([ \\t]+)${name}: (.+)$`, "gmu"))];
  if (declarations.length !== 1 || declarations[0][1] !== "  " || declarations[0][2] !== version) {
    fail("protobuf tools must be pinned exactly once at workflow scope");
  }
}
assertWorkflowRunStep(protobufWorkflow, "Install buf", `set -euo pipefail
install_dir="$RUNNER_TEMP/buf/bin"
mkdir -p "$install_dir"
curl --fail-with-body --location --proto '=https' --tlsv1.2 \\
  --retry 5 --retry-all-errors \\
  --output "$install_dir/buf" \\
  "https://github.com/bufbuild/buf/releases/download/v\${BUF_VERSION}/buf-Linux-x86_64"
printf '%s  %s\\n' "$BUF_LINUX_X86_64_SHA256" "$install_dir/buf" \\
  | sha256sum --check --strict
chmod 0755 "$install_dir/buf"
printf '%s\\n' "$install_dir" >> "$GITHUB_PATH"
"$install_dir/buf" --version`);
assertWorkflowRunStep(protobufWorkflow, "Install pinned Buffa generators",
  `cargo install reallyme-protoc-gen-buffa --version "=$BUFFA_VERSION" --locked
cargo install reallyme-protoc-gen-buffa-packaging --version "=$BUFFA_VERSION" --locked`);
assertWorkflowRunStep(protobufWorkflow, "Check protobuf compatibility with the V2 contract",
  'buf breaking --against "$PROTOBUF_BASELINE_FILE"', "protobuf");
assertContains(protobufWorkflow, "PROTOBUF_BASELINE_FILE: crates/proto/compatibility/v2.binpb");
assertWorkflowRunStep(protobufWorkflow, "Check release readiness generated freshness",
  protobufFirstPolicy.verification.run, "protobuf");
for (const step of extractWorkflowSteps(protobufWorkflow)) {
  if (step.name !== "Check release readiness generated freshness" &&
      typeof step.run === "string" && /(?:^|\n)\s*buf\s+(?:lint|generate)\b/u.test(step.run)) {
    fail("protobuf workflow must delegate lint and generation to the freshness gate");
  }
}
const [protoSchema] = protobufFirstPolicy.schemaPaths;
const scalarFieldClassifications = [];
for (const { name, body, rawBody } of schemaMessages(readText(protoSchema))) {
  for (const field of body.matchAll(/^[ \t]*(?:(?:optional|repeated)\s+)?(bytes|string)\s+(\w+)\s*=\s*\d+/gmu)) {
    const precedingComment = /(?:^[ \t]*\/\/[^\n]*\n)+$/mu.exec(rawBody.slice(0, field.index))?.[0];
    if (!precedingComment?.includes("SENSITIVE:")) {
      fail(`${protoSchema} must classify ${name}.${field[2]} as sensitive`);
    }
    scalarFieldClassifications.push({ message: name, field: field[2], kind: field[1], sensitivity: "sensitive" });
  }
}
assertReallyMeProtobufReleasePolicy({
  workflow: protobufWorkflow,
  workflowMode: "delegated",
  generatedFreshnessStepRun: protobufFirstPolicy.verification.run,
  bufVersion: "1.75.0",
  buffaVersion,
  protobufFirst: protobufFirstPolicy,
  hardeningPolicy: {
    protoSchema,
    generatedRust: "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
    scalarFieldClassifications,
  },
  generatedFreshnessMode,
  generatedFreshness: {
    generatedPaths: [
      "crates/proto/src/generated", "crates/jose/src", "crates/ffi/src/generated_contract", "gen/swift", "gen/java", "gen/kotlin",
      "packages/ts/src", "packages/swift/Sources/ReallyMeJOSE", "packages/kotlin/src/main/kotlin/me/really/jose",
    ],
    commands: [
      ["buf", ["lint"]],
      ["buf", ["generate"]],
      ["node", ["scripts/generate-contract-values.mjs"]],
      ["node", ["scripts/harden-generated-jose-jvm.mjs"]],
      ["node", ["scripts/harden-generated-jose-swift.mjs"]],
      ["cargo", ["fmt", "--package", "reallyme-jose-proto"]],
      ["node", ["scripts/generate-contract-values.mjs", "--check"]],
      ["node", ["scripts/harden-generated-jose-jvm.mjs", "--check-idempotent"]],
      ["node", ["scripts/harden-generated-jose-swift.mjs", "--check-idempotent"]],
    ],
  },
});

assertContains(".github/workflows/crates-package-preflight.yml", `BUFFA_VERSION: ${buffaVersion}`);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/harden-generated-jose-jvm.mjs --check-idempotent",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "node scripts/harden-generated-jose-swift.mjs --check-idempotent",
);
assertContains("gen/swift/reallyme/jose/v1/jose.pb.swift", "ReallyMeProtoJoseJwsSignRequest(<redacted>)");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "crates/proto/src gen/swift gen/java gen/kotlin packages/ts/src/proto/generated",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "package reallyme.jose.v1;");
assertProtoContract("crates/proto/proto/reallyme/jose/v1/jose.proto");
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  'option go_package = "github.com/reallyme/jose/gen/go/reallyme/jose/v1;josev1";',
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "option java_multiple_files = true;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", 'option java_outer_classname = "JoseProto";');
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", 'option java_package = "me.really.jose.v1";');
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", 'option swift_prefix = "ReallyMeProto";');
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseError");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JosePrimitiveError primitive = 1;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseProviderError provider = 2;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseBackendError backend = 3;");
assertNotContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JwsError jws = 1;");
assertNotContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JweError jwe = 2;");
assertNotContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JwtError jwt = 3;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "enum JoseErrorReason");
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  '"JOSE_ERROR_REASON_JWS_INVALID_COMPACT"',
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  '"JOSE_ERROR_REASON_JWE_INVALID_COMPACT"',
);
for (const errorReason of [
  "JOSE_ERROR_REASON_JWE_UNSUPPORTED_COMPRESSION_ALGORITHM = 228;",
  "JOSE_ERROR_REASON_JWE_COMPRESSION_FAILED = 261;",
  "JOSE_ERROR_REASON_JWE_DECOMPRESSION_FAILED = 262;",
  "JOSE_ERROR_REASON_JWE_DECOMPRESSED_PLAINTEXT_TOO_LARGE = 263;",
]) {
  assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", errorReason);
}
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  '"JOSE_ERROR_REASON_JWT_INVALID_COMPACT"',
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH = 327;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY = 328;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_JWK = 329;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME = 385;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY = 386;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_AUDIENCE_MISMATCH = 390;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF = 700;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_COMMON_MALFORMED_JSON = 701;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_COMMON_MISSING_OPERATION = 702;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED = 703;",
);
assertNotContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_ERROR_REASON_JWE_RANDOMNESS_FAILED");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "signature_only");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "uint64 now_unix = 6;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "string expected_audience = 7;");
assertRawContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "expiration validation fail open",
  "the expiration-presence rationale",
);
assertRawContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "Required to be nonzero",
  "the temporal-policy nonzero requirement",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseOperationResponse");
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JoseOperationContractVersion contract_version = 10;",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseError boundary_error = 900;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseJwsVerifyResponse jws_verify = 1001;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseJwtVerifyResponse jwt_verify = 2003;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseJweDecryptResponse jwe_decrypt = 3001;");
assertNotMatches(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  /message\s+JoseOperationResponse\s*\{[^}]*\bbytes\s+payload\b/su,
  "an opaque payload in JoseOperationResponse",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseOperationRequest");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "reserved 1 to 8;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseJwsSignRequest jws_sign = 1000;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseJwtSignRequest jwt_sign = 2002;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseJweDecryptRequest jwe_decrypt = 3001;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_SIGNATURE_ALGORITHM_EDDSA = 100;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_SIGNATURE_ALGORITHM_ES256 = 200;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT = 100;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256 = 200;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM = 100;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM = 120;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "enum JoseJweCompressionAlgorithm");
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_JWE_COMPRESSION_ALGORITHM_DEFLATE = 100;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JoseJweCompressionAlgorithm compression_algorithm = 10;",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseJwsSignRequest");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseJwtSignRequest");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseJweEncryptRequest");
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  '.field("private_key", &::core::format_args!("[REDACTED]"))',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  '.field("plaintext", &::core::format_args!("[REDACTED]"))',
);
assertContains("buf.gen.yaml", "borrowed_views_only_in=.reallyme.jose.v1");
assertNotContains("crates/proto/src/generated/buffa/reallyme.jose.v1.jose.__view.rs", "JoseJwsSignRequestOwnedView");
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  "::buffa::sensitive::Zeroize::zeroize(&mut self.private_key);",
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  '.field("private_key", &self.private_key)',
);
assertNotContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  '.field("plaintext", &self.plaintext)',
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JoseJweHeaderValidationPolicy header_policy = 5;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "message JoseJweHeaderValidationPolicy",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "bool require_kid = 1;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseExpectedString expected_kid = 2;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseExpectedString expected_typ = 3;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseExpectedString expected_cty = 4;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseExpectedBytes expected_apu = 5;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "JoseExpectedBytes expected_apv = 6;");
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "repeated JoseJweCompressionAlgorithm allowed_compression_algorithms = 7;",
);
assertRawContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "Adapters must zeroize after dispatch",
  "the adapter zeroization contract",
);
assertRawContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "Presence-sensitive policy",
  "the presence-sensitive policy rationale",
);
assertRawContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "Sensitive decrypted plaintext bytes",
  "the decrypted-plaintext sensitivity rationale",
);
assertNotMatches(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  /^\s*service\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/mu,
  "a protobuf service declaration",
);
assertNotContains("crates/jose/src/jwe/encrypt.rs", "new_with_ephemeral_private_key");
assertContains("crates/jose/src/wire/operation_response.rs", "pub fn execute_operation_v1<");
assertContains("crates/jose/src/wire/operation_response.rs", "pub fn execute_operation_json_v1<");
assertContains("crates/jose/src/wire/operation_response.rs", "pub fn decode_operation_response_v1(");
assertContains("crates/jose/src/wire/operation_response.rs", "JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V2");
assertContains(
  "crates/jose/tests/operation_response_tests.rs",
  "all_operations_match_binary_and_proto_json_routes",
);
assertContains(
  "crates/jose/tests/operation_response_tests.rs",
  "canonical_decoder_accepts_every_stable_error_branch_and_reason",
);
assertContains(
  "crates/jose/tests/operation_response_tests.rs",
  "protojson_request_rejects_duplicate_and_unknown_members",
);
assertContains(
  "crates/jose/tests/validate_jwe_header.rs",
  "public_header_deserialization_rejects_dangerous_and_duplicate_members",
);
assertContains("crates/jose/tests/jwt_suite/unsigned_reject_tests.rs", "reject_unsigned_with_duplicate_header_member");
assertContains("crates/jose/tests/jwt_suite/unsigned_reject_tests.rs", "reject_unsigned_with_critical_header_parameter");
assertContains("crates/jose/tests/jwt_suite/unsigned_reject_tests.rs", "reject_unsigned_with_duplicate_claim_member");
assertContains("crates/jose/tests/jwt_suite/signed_reject_tests.rs", "reject_signed_jwt_with_duplicate_claim_members");
assertContains("crates/jose/tests/jwt_suite/signed_reject_tests.rs", "reject_signed_eddsa_jwt_with_wrong_signature_length");
assertContains("crates/jose/tests/jwe_tests/cases.rs", "rejects_ecdh_es_epk_with_private_member");
assertContains("crates/jose/tests/jwe_tests/negative_cases.rs", "rejects_duplicate_epk_member");
assertContains("crates/jose/tests/jwe_tests/negative_cases.rs", "rejects_direct_jwe_with_ecdh_ephemeral_key_headers");
assertContains(
  "crates/jose/tests/jwe_tests/support_and_boundaries.rs",
  "rejects_invalid_ecdh_es_shared_secret_length_before_kdf",
);
assertContains("crates/jose/tests/jws_es256_tests.rs", "jws_es256_rejects_all_zero_signature_scalars");
assertContains("crates/jose/tests/jws_es256_tests.rs", "jws_es256_rejects_r_scalar_at_group_order");
assertContains("crates/jose/tests/jws_es256_tests.rs", "jws_es256_rejects_s_scalar_at_group_order");
assertContains("crates/jose/tests/jws_es256_tests.rs", "jws_es256_accepts_high_s_signature_as_valid_ecdsa");
assertContains(
  "crates/proto/tests/generated_tests.rs",
  "jose_operation_request_wire_contract_is_stable",
);
assertContains(
  "crates/proto/tests/generated_tests.rs",
  "JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8.to_i32()",
);
assertContains(
  "crates/proto/tests/generated_tests.rs",
  "JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64.to_i32()",
);
assertNotContains("crates/jose/src/lib.rs", "crates/envelopes");
assertContains("crates/jose/src/lib.rs", "requires a supported runtime lane");
assertContains(".github/workflows/rust-ci.yml", "Check no-feature guidance");
assertContains(".github/workflows/rust-ci.yml", "cargo check --locked --workspace --all-features");
assertContains(rustWorkflow, releaseRustTest);
assertContains(".github/workflows/rust-ci.yml", "Test publishable crates in the release profile");
assertContains(".github/workflows/rust-ci.yml", "cargo nextest run --release --locked -p reallyme-jose");
assertContains(".github/workflows/rust-ci.yml", "Format vector audit tool");
assertContains(".github/workflows/rust-ci.yml", "Independent vector audit");
assertContains(".github/workflows/rust-ci.yml", "--bin reallyme-jose-vector-audit -- .");
assertContains(".github/workflows/rust-ci.yml", "scripts/audit_committed_lockfiles.sh");
assertContains(".github/workflows/rust-ci.yml", "CARGO_CHECK_EXTERNAL_TYPES_VERSION: 0.5.0");
assertContains(".github/workflows/rust-ci.yml", "EXTERNAL_TYPES_NIGHTLY: nightly-2026-03-20");
assertContains(
  ".github/workflows/rust-ci.yml",
  "run: scripts/check_public_external_types.sh",
);
assertContains(
  "scripts/check_public_external_types.sh",
  "--manifest-path crates/jose/Cargo.toml --all-features",
);
assertContains("scripts/check_public_external_types.sh", 'readonly TOOLCHAIN="nightly-2026-03-20"');
assertContains("scripts/check_public_external_types.sh", "rustdoc --locked --ignore-rust-version");
assertContains("scripts/check_public_external_types.sh", "cargo-check-external-types check-external-types");
assertContains(".github/workflows/rust-ci.yml", "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER");
assertContains(".github/workflows/rust-ci.yml", "--test panva_vectors");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER",
);
assertContains(".github/workflows/crates-package-preflight.yml", "--test panva_vectors");
assertContains(rustWorkflow, cargoDenyInstall);
assertContains(".github/workflows/rust-ci.yml", "cargo-audit@0.23.0");
assertContains(".github/workflows/crates-package-preflight.yml", "cargo fmt --check");
assertNotContains(".github/workflows/crates-package-preflight.yml", "Check warnings as errors");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "Test publishable crates in the release profile",
);
assertContains(".github/workflows/crates-package-preflight.yml", "scripts/audit_committed_lockfiles.sh");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "run: scripts/check_public_external_types.sh",
);
assertContains(".github/workflows/rust-ci.yml", "CARGO_NEXTEST_VERSION: 0.9.152");
assertContains(".github/workflows/crates-package-preflight.yml", "CARGO_NEXTEST_VERSION: 0.9.152");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo-deny@0.22.0",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo-audit@0.23.0",
);
assertContains("deny.toml", "unknown-registry = \"deny\"");
assertContains("deny.toml", 'yanked = "deny"');
assertContains("deny.toml", 'multiple-versions = "deny"');
assertNotContains("Cargo.toml", "getrandom02");
assertNotContains("crates/jose/Cargo.toml", "getrandom02");
assertNotContains("deny.toml", 'name = "getrandom", version = "0.2.17"');
assertContains("deny.toml", 'name = "syn", version = "2.0.119"');

assertNotContains("crates/ffi/src/lib.rs", '#![allow(unsafe_code)]');
for (const boundaryModule of ["pointer", "operation", "owned_response", "kotlin"]) {
  assertContains(`crates/ffi/src/${boundaryModule}.rs`, '#![allow(unsafe_code)]');
}
assertContains("crates/ffi/src/lib.rs", '#[cfg(not(panic = "unwind"))]');
assertContains("crates/ffi/src/lib.rs", "compile_error!");
assertNotContains("crates/ffi/src/lib.rs", "#![allow(warnings)]");
for (const symbol of [
  "rm_jose_abi_version",
  "rm_jose_max_request_bytes",
  "rm_jose_max_json_request_bytes",
  "rm_jose_max_response_bytes",
  "rm_jose_execute_operation_v1",
  "rm_jose_execute_operation_json_v1",
  "rm_jose_zeroize_buffer",
]) {
  assertContains("crates/ffi/src/operation.rs", `fn ${symbol}`);
  assertContains("crates/ffi/include/reallyme_jose.h", symbol);
  assertContains("scripts/test_ffi_abi_release_artifact.sh", symbol);
}
for (const symbol of [
  "rm_jose_execute_owned_operation_v1",
  "rm_jose_execute_owned_operation_json_v1",
  "rm_jose_owned_response_view_v1",
  "rm_jose_owned_response_release_v1",
]) {
  assertContains("crates/ffi/src/owned_response.rs", `fn ${symbol}`);
  assertContains("crates/ffi/include/reallyme_jose.h", symbol);
  assertContains("scripts/test_ffi_abi_release_artifact.sh", symbol);
}
assertContains("crates/ffi/src/operation.rs", "execute_operation_v1(request, rng)");
assertContains("crates/ffi/src/operation.rs", "execute_operation_json_v1(request, rng)");
assertNotContains("crates/ffi/src/operation.rs", "jws::");
assertNotContains("crates/ffi/src/operation.rs", "jwt::");
assertNotContains("crates/ffi/src/operation.rs", "jwe::");
assertContains("crates/ffi/src/operation.rs", "checked_add(1)");
assertContains("crates/ffi/src/operation.rs", "Zeroizing<Vec<u8>>");
assertContains("crates/ffi/src/operation.rs", "response.zeroize()");
assertContains("crates/ffi/src/pointer.rs", ".checked_add(first_len)");
assertContains("crates/ffi/src/pointer.rs", ".checked_add(second_len)");
assertContains("crates/ffi/src/pointer.rs", "ptr.addr().checked_add(len)");
assertContains("crates/ffi/src/pointer.rs", "validate_disjoint_ranges(");
assertContains("crates/ffi/src/pointer.rs", "core::slice::from_raw_parts(");
assertContains("crates/ffi/src/pointer.rs", "core::slice::from_raw_parts_mut(");
assertContains("crates/ffi/src/guard.rs", "std::panic::catch_unwind");
assertContains("crates/ffi/src/guard.rs", "catch_boundary_unwind");
assertContains("crates/ffi/src/kotlin.rs", "catch_boundary_unwind");
assertContains("crates/ffi/src/guard.rs", "INSIDE_JOSE_BOUNDARY");
assertContains("crates/ffi/src/guard.rs", "previous(panic_info)");
assertNotContains("crates/ffi/src/guard.rs", "resume_unwind");
for (const status of [
  "RM_JOSE_OK = 0",
  "RM_JOSE_CALLER_ERROR = -1",
  "RM_JOSE_PROVIDER_ERROR = -2",
  "RM_JOSE_BACKEND_ERROR = -3",
  "RM_JOSE_PANIC_CAUGHT = -4",
  "RM_JOSE_OUTPUT_CAPACITY_MISMATCH = -5",
  "RM_JOSE_UNSUPPORTED_ABI = -6",
]) {
  assertContains("crates/ffi/include/reallyme_jose.h", status);
}
assertRawContains(
  "crates/ffi/include/reallyme_jose.h",
  "All nonempty ranges must identify one live allocation",
  "the live-allocation contract",
);
assertRawContains(
  "crates/ffi/include/reallyme_jose.h",
  "mutually disjoint",
  "the range-disjointness contract",
);
assertMarkdownContains("crates/ffi/README.md", "caller-owned buffer cleanup");
assertMarkdownContains("crates/ffi/README.md", "must not infer");
assertMarkdownContains("crates/ffi/README.md", "semantic errors from the C status alone");
for (const testName of [
  "binary_and_proto_json_routes_match_for_every_operation",
  "capacity_mismatch_reports_exact_length_without_modifying_output",
  "unsupported_abi_and_invalid_pointer_fail_with_zero_length",
  "overlapping_input_and_output_are_rejected_before_mutation",
  "oversized_sentinel_preserves_resource_limit_but_larger_input_is_rejected",
  "zeroize_export_clears_exact_caller_owned_range",
  "zeroize_export_rejects_wrapping_address_range",
  "probe_and_write_lengths_match_for_every_operation",
  "probe_and_write_lengths_match_for_randomized_jwe",
  "concurrent_calls_have_independent_outputs",
]) {
  assertContains("crates/ffi/tests/abi.rs", testName);
}
assertContains("crates/ffi/src/guard_tests.rs", "panic_payload_is_caught_and_mapped_without_escape");
assertContains(
  "crates/ffi/src/guard_tests.rs",
  "extern_boundary_maps_deliberate_panic_to_stable_status",
);
assertContains("scripts/test_ffi_abi_release_artifact.sh", "header_smoke.c");
assertContains("scripts/test_ffi_abi_release_artifact.sh", "-u CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/test_ffi_abi_release_artifact.sh", "--profile release-ffi");
assertNotContains("scripts/test_ffi_abi_release_artifact.sh", "-C panic=unwind");
assertContains("scripts/test_ffi_abi_release_artifact.sh", '"${NM_TOOL}" -g');
assertContains("scripts/test_native_sanitizers.sh", "nightly-2026-09-15");
assertContains("scripts/test_native_sanitizers.sh", "-Zsanitizer=address");
assertContains("scripts/test_native_sanitizers.sh", "-Zub-checks=yes");
assertContains("scripts/test_native_sanitizers.sh", "-Zextra-const-ub-checks=yes");
assertContains(".github/workflows/rust-ci.yml", "scripts/test_ffi_abi_release_artifact.sh");
assertContains(".github/workflows/rust-ci.yml", "scripts/test_native_sanitizers.sh");

assertRawContains("Package.swift", "// swift-tools-version: 6.3", "the Swift tools version directive");
assertContains("Package.swift", 'name: "reallyme-jose"');
assertContains("Package.swift", '.macOS(.v13)');
assertContains("Package.swift", '.iOS(.v16)');
assertContains("Package.swift", 'name: "ReallyMeJOSE"');
assertContains("Package.swift", 'exact: "1.41.0"');
assertContains("Package.swift", 'path: "gen/swift"');
assertContains("Package.swift", `ffiReleaseVersion = "${crateVersion}"`);
if (!/^let ffiArtifactVersion = "[0-9]+\.[0-9]+\.[0-9]+"$/mu.test(readText("Package.swift"))) {
  fail("Package.swift must pin a published Swift binary version");
}
assertContains("Package.swift", 'ffiArtifactLocalPathOverride = ""');
assertNotContains("Package.swift", "0000000000000000000000000000000000000000000000000000000000000000");
assertContains("Package.swift", "REALLYME_JOSE_SWIFTPM_RUNTIME_FFI");
assertContains("Package.swift", ".reallyme-jose-runtime-ffi");
assertContains("Package.swift", "FileManager.default.fileExists");
assertContains("Package.swift", 'https://github.com/reallyme/jose/releases/download/v\\(ffiArtifactVersion)/ReallyMeJOSEFFI.xcframework.zip');
assertContains("Package.resolved", '"version" : "1.41.0"');
assertContains("gen/swift/reallyme/jose/v1/jose.pb.swift", "public nonisolated struct ReallyMeProtoJoseOperationRequest");
assertContains("gen/swift/reallyme/jose/v1/jose.pb.swift", "public nonisolated struct ReallyMeProtoJoseOperationResponse");
assertContains(
  "Package.swift",
  '.library(name: "ReallyMeJOSEProto", targets: ["ReallyMeJOSEProto"])',
);

for (const method of [
  "signJWS(",
  "verifyJWS(",
  "encodeUnsignedJWT(",
  "decodeUnsignedJWT(",
  "signJWT(",
  "verifyJWT(",
  "encryptJWE(",
  "decryptJWE(",
  "executeWireRequest(",
  "executeWireJSONRequest(",
]) {
  assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", method);
}
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "addingReportingOverflow");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "messageDepthLimit = JoseContractValues.protoRecursionDepth");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "provider.clearOwned(&requestBytes)");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "provider.clearOwned(&responseBytes)");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "clearOwned(&result.protectedHeaderJson)");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "clearOwned(&result.payload)");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "response.contractVersion == .v2");
assertContains("packages/swift/Sources/ReallyMeJOSE/OperationContract.swift", "ReallyMeJOSEErrorReason(rawValue: protoReason.rawValue)");
assertContains("packages/swift/Sources/ReallyMeJOSE/MemoryHygiene.swift", "memset_s");
assertContains("packages/swift/Sources/ReallyMeJOSE/MemoryHygiene.swift", "canImport(Glibc)");
assertContains("packages/swift/Sources/ReallyMeJOSE/MemoryHygiene.swift", "explicit_bzero");
assertContains("scripts/test_swift_source_tree.sh", '"$(uname -s)" != "Darwin"');
assertContains("packages/swift/Sources/ReallyMeJOSE/NativeProvider.swift", "try Self.requireCompatibleABI(version())");
assertRawContains(
  "packages/swift/Sources/ReallyMeJOSE/NativeProvider.swift",
  "Resolve no operational symbol until",
  "the ABI-resolution ordering rationale",
);
assertContains("packages/swift/Sources/ReallyMeJOSE/NativeProvider.swift", "rm_jose_zeroize_buffer");
assertContains("packages/swift/Sources/ReallyMeJOSE/ContractValues.swift", "public enum ReallyMeJOSEErrorReason: Int");
assertContains("packages/swift/Sources/ReallyMeJOSE/Errors.swift", "case jose(branch:");
assertNotContains("packages/swift/Sources/ReallyMeJOSE/Errors.swift", "String");
for (const file of listFiles("packages/swift/Sources/ReallyMeJOSE").filter((path) => path.endsWith(".swift"))) {
  const source = readText(file);
  if (source.split("\n").length > 500) fail(`${file} exceeds the Swift production source line limit`);
  for (const forbidden of ["CustomStringConvertible", "CustomDebugStringConvertible", "fatalError(", "preconditionFailure(", "print("]) {
    if (source.includes(forbidden)) fail(`${file} contains forbidden Swift production token ${forbidden}`);
  }
}
for (const testName of [
  "jwsKnownAnswerAndTypedFailure",
  "jwsSigningUsesCanonicalRustRoute",
  "unsignedJWTAndDirectJWERoundTrip",
  "signedJWTAndPolicyRoundTrip",
  "oversizedManagedInputFailsBeforeNativeCopy",
  "linkedXCFrameworkExecutesOperationContract",
  "memoryClearerZeroizesOwnedBuffers",
]) {
  assertContains("packages/swift/Tests/ReallyMeJOSETests/ReallyMeJOSETests.swift", testName);
}
assertMarkdownContains("packages/swift/README.md", "copy-on-write aliases");
assertMarkdownContains("packages/swift/README.md", "Runtime loading is an explicit integration/testing mode");
assertMarkdownContains("packages/swift/README.md", '.product(name: "ReallyMeJOSEProto", package: "jose")');
assertContains("scripts/build_swift_xcframework.sh", "aarch64-apple-darwin");
assertContains("scripts/build_swift_xcframework.sh", "x86_64-apple-darwin");
assertContains("scripts/build_swift_xcframework.sh", "aarch64-apple-ios");
assertContains("scripts/build_swift_xcframework.sh", "aarch64-apple-ios-sim");
assertContains("scripts/build_swift_xcframework.sh", "x86_64-apple-ios");
assertContains("scripts/build_swift_xcframework.sh", "--profile release-ffi");
assertContains("scripts/build_swift_xcframework.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertNotContains("scripts/build_swift_xcframework.sh", "-C panic=unwind");
assertContains("scripts/build_swift_xcframework.sh", "verify_xcframework_layout");
assertContains("scripts/build_swift_xcframework.sh", "swift package compute-checksum");
assertContains("scripts/verify_swift_release_artifact.mjs", "archive and sidecar checksums differ");
assertContains("scripts/verify_swift_release_artifact.mjs", "requiredSymbols");
assertContains("scripts/verify_swift_release_artifact.mjs", "Rust LLVM symbol inspector");
assertContains("Cargo.toml", 'rust-version = "1.100"');
assertContains("fuzz/Cargo.toml", 'rust-version = "1.100"');
assertContains("tools/vector-audit/Cargo.toml", 'rust-version = "1.99"');
assertContains("rust-toolchain.toml", `channel = "${releaseRust}"`);
assertContains("rust-toolchain.toml", 'components = ["clippy", "llvm-tools-preview", "rustfmt"]');
for (const workflow of listFiles(".github/workflows").filter((path) => path.endsWith(".yml"))) {
  for (const [, version] of readText(workflow).matchAll(/^[ \t]+toolchain:[ \t]+(1\.\d+\.\d+)[ \t]*$/gmu)) {
    if (version !== releaseRust && !(workflow === rustWorkflow && version === minimumRust)) {
      fail(`${workflow} pins Rust ${version} instead of the supported ${releaseRust} release`);
    }
  }
}
assertContains("scripts/prepare_swift_binary_manifest.mjs", "invalid-local-artifact-path");
assertContains("scripts/prepare_swift_release_candidate.sh", "scripts/build_swift_xcframework.sh");
assertContains(".github/workflows/swift-ci.yml", "runs-on: macos-26");
assertContains(".github/workflows/swift-ci.yml", "Select Xcode 26.6");
assertContains(".github/workflows/swift-ci.yml", "components: llvm-tools-preview");
assertContains(".github/workflows/swift-ci.yml", "scripts/build_swift_xcframework.sh");
assertContains(".github/workflows/swift-ci.yml", ".reallyme-jose-runtime-ffi");
assertContains(".github/workflows/swift-package-preflight.yml", "Upload Swift release candidate");
assertContains(".github/workflows/swift-package-preflight.yml", "macos-26");
assertContains(".github/workflows/swift-package-preflight.yml", "Select Xcode 26.6");
assertContains(".github/workflows/swift-package-preflight.yml", "components: llvm-tools-preview");
assertContains(".github/workflows/swift-package-preflight.yml", "verify_swift_release_artifact.test.mjs");
assertContains(
  ".github/workflows/swift-package-preflight.yml",
  `${releaseReadinessCommand} --release-packages --policy-only`,
);
assertContains(".github/workflows/rust-ci.yml", "--profile release-ffi");
assertContains(".github/workflows/rust-ci.yml", "name: MSRV 1.100");
assertContains(rustWorkflow, `toolchain: ${minimumRust}`);
const swiftPreflightSource = readText(".github/workflows/swift-package-preflight.yml");
if (swiftPreflightSource.indexOf("Upload Swift release candidate") <=
    swiftPreflightSource.indexOf("Test Swift package with linked binary target")) {
  fail("Swift package preflight must verify the linked artifact before uploading it");
}
const swiftReleaseWorkflow = ".github/workflows/swift-package-release.yml";
assertContains(swiftReleaseWorkflow, "SwiftPM artifact verification");
assertContains(swiftReleaseWorkflow, "components: llvm-tools-preview");
assertContains(swiftReleaseWorkflow, "Download verified package");
assertContains(swiftReleaseWorkflow, "Bind manifest to attested Swift artifact");
assertContains(swiftReleaseWorkflow, "Verify SwiftPM manifest and downloaded artifact");
assertContains(swiftReleaseWorkflow, "Bind release manifest to verified Swift artifact");
assertContains(swiftReleaseWorkflow, "Create immutable GitHub release with Swift artifact");
assertContains(swiftReleaseWorkflow, "runs-on: macos-26");
assertContains(swiftReleaseWorkflow, "Select Xcode 26.6");
assertContains(swiftReleaseWorkflow, "environment: github-release");
assertContains(swiftReleaseWorkflow, 'GitHub release v${RELEASE_VERSION} already exists');
assertContains(
  swiftReleaseWorkflow,
  'Git tag v${RELEASE_VERSION} already targets a different commit',
);
assertContains(swiftReleaseWorkflow, "gh release create");
assertContains(swiftReleaseWorkflow, "--notes-file -");
assertContains(
  swiftReleaseWorkflow,
  "- introduce the V2 protobuf operation contract with explicit field presence and schema-defined operation reasons",
);
assertContains(
  swiftReleaseWorkflow,
  "- preserve platform-specific SDK setup errors and expose their schema-defined codes",
);
assertContains(
  swiftReleaseWorkflow,
  `- generate Rust protobuf memory cleanup and redaction with ReallyMe Buffa ${buffaVersion}`,
);
assertContains(
  swiftReleaseWorkflow,
  `- use ReallyMe Codec ${codecVersion} for the shared native and WASM runtime`,
);
assertContains(
  swiftReleaseWorkflow,
  `- use ReallyMe Crypto ${cryptoVersion} for the shared cryptographic operations`,
);
assertContains(swiftReleaseWorkflow, "- regenerate SDK bindings and rebuild native binaries together for V2");
assertContains(swiftReleaseWorkflow, 'git tag "v${RELEASE_VERSION}" "${tag_target}"');
assertContains(swiftReleaseWorkflow, "--verify-tag");
assertContains(
  swiftReleaseWorkflow,
  `${releaseReadinessCommand} --release-packages --policy-only`,
);
assertNotContains(swiftReleaseWorkflow, "scripts/build_swift_xcframework.sh");
assertNotContains(swiftReleaseWorkflow, "--clobber");
assertNotContains(swiftReleaseWorkflow, "gh release edit");
const swiftReleaseSource = readText(swiftReleaseWorkflow);
const swiftPublishJob = swiftReleaseSource.slice(swiftReleaseSource.indexOf("  swift-release:"));
if (swiftPublishJob.includes("persist-credentials: false")) {
  fail("Swift release tag job must retain the scoped checkout credential required to push its tag");
}
const swiftArtifactVerificationCount = swiftReleaseSource.match(
  /node scripts\/verify_swift_release_artifact[.]mjs/gu,
)?.length;
if (swiftArtifactVerificationCount !== 2) {
  fail("Swift release workflow must verify the attested archive in both verification jobs");
}
let previousSwiftReleaseBoundary = -1;
for (const boundary of [
  "swift-verify:",
  "Bind manifest to attested Swift artifact",
  "Verify SwiftPM manifest and downloaded artifact",
  "swift-release:",
  "Bind release manifest to verified Swift artifact",
  "Create immutable GitHub release with Swift artifact",
]) {
  const boundaryIndex = swiftReleaseSource.indexOf(boundary);
  if (boundaryIndex <= previousSwiftReleaseBoundary) {
    fail(`Swift release workflow boundary is missing or out of order: ${boundary}`);
  }
  previousSwiftReleaseBoundary = boundaryIndex;
}
assertWorkflowPermissionsPolicy({
  path: swiftReleaseWorkflow,
  workflow: { contents: "read" },
  jobs: {
    "verify-release-sha": { actions: "read", contents: "read" },
    "swift-verify": { actions: "read", contents: "read" },
    "swift-release": { actions: "read", contents: "write" },
  },
});

const npmPreflightWorkflow = ".github/workflows/npm-package-preflight.yml";
const npmReleaseWorkflow = ".github/workflows/npm-package-release.yml";
assertContains(npmPreflightWorkflow, "npm --prefix packages/ts test");
assertContains(npmPreflightWorkflow, "npm --prefix packages/ts run pack:check");
assertContains(npmPreflightWorkflow, "Build immutable npm tarball");
assertContains(npmPreflightWorkflow, "Upload immutable npm tarball");
assertContains(npmReleaseWorkflow, "Download verified package");
assertContains(npmReleaseWorkflow, "sha256sum --check");
assertContains(npmReleaseWorkflow, 'npm publish "reallyme-jose-${RELEASE_VERSION}.tgz" --provenance --access public');
assertNotMatches(npmReleaseWorkflow, /(?:^|\n)\s*(?:run:\s*)?npm pack(?:\s|$)/u, "npm repackaging");
assertNotContains(npmReleaseWorkflow, "npm publish .");
assertWorkflowPermissionsPolicy({
  path: npmReleaseWorkflow,
  workflow: { contents: "read" },
  jobs: {
    "verify-release-sha": { actions: "read", contents: "read" },
    publish: { actions: "read", contents: "read", "id-token": "write" },
  },
});
assertContains("Cargo.toml", 'jni = "0.22.4"');
assertContains("crates/ffi/Cargo.toml", "jni = { workspace = true }");
assertContains("crates/ffi/src/lib.rs", "mod kotlin;");
assertNotContains("crates/ffi/src/lib.rs", "pub mod kotlin;");
assertContains("crates/ffi/src/kotlin.rs", "Java_me_really_jose_ReallyMeJoseNative_executeOperationNative");
assertContains("crates/ffi/src/kotlin.rs", "rm_jose_execute_owned_operation_v1");
assertContains("crates/ffi/src/kotlin.rs", "Zeroizing<Vec<u8>>");
assertContains("packages/kotlin/build.gradle.kts", 'kotlin("jvm") version "2.4.21"');
assertContains("packages/kotlin/build.gradle.kts", "jvmToolchain(21)");
assertContains("packages/kotlin/build.gradle.kts", "lockAllConfigurations()");
assertContains("packages/kotlin/build.gradle.kts", 'api("com.google.protobuf:protobuf-javalite:4.36.2")');
assertContains("packages/kotlin/build.gradle.kts", 'val bouncyCastleToolVersion = "1.87"');
assertContains("packages/kotlin/gradle.lockfile", "org.bouncycastle:bcprov-jdk18on:1.87=kotlinBouncyCastleConfiguration");
assertContains("packages/kotlin/build.gradle.kts", "verifyJarContainsNativeResources");
assertContains("packages/kotlin/build.gradle.kts", "verifyJvmNativeManifest(");
assertContains("packages/kotlin/build.gradle.kts", "JVM native manifest source SHA does not match the checkout");
assertContains("packages/kotlin/build.gradle.kts", "verifyRemoteMavenPublishingConfigured");
assertNotContains("packages/kotlin/build.gradle.kts", "if (signingKeyValue != null)");
assertContains("packages/kotlin/gradle.properties", "org.gradle.dependency.verification=strict");
assertContains("packages/kotlin/gradle/wrapper/gradle-wrapper.properties", "distributionSha256Sum=");
assertContains("packages/kotlin/gradle/wrapper/gradle-wrapper.properties", "networkTimeout=30000");
assertContains("packages/kotlin/gradle/wrapper/gradle-wrapper.properties", "retries=3");
assertContains("packages/kotlin/gradle/wrapper/gradle-wrapper.properties", "retryBackOffMs=1000");
assertContains("packages/kotlin/gradle/verification-metadata.xml", "<sha256 value=");
for (const method of [
  "signJws(",
  "verifyJws(",
  "encodeUnsignedJwt(",
  "decodeUnsignedJwt(",
  "signJwt(",
  "verifyJwt(",
  "encryptJwe(",
  "decryptJwe(",
  "executeWireRequest(",
  "executeWireJsonRequest(",
]) {
  assertContains("packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt", method);
}
assertContains("packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt", "Math.addExact");
assertContains("packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt", "requestBytes.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt", "responseBytes.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt", "reallyMeHasUnknownFieldsForValidation");
assertContains("packages/kotlin/src/main/kotlin/me/really/jose/RustNativeProvider.kt", "MessageDigest.isEqual");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/jose/NativeExtractionPolicy.kt",
  'PosixFilePermissions.fromString("rwx------")',
);
assertContains("scripts/harden-generated-jose-jvm.mjs", "reallyMeHasUnknownFieldsForValidation");
assertContains("scripts/harden-generated-jose-jvm.mjs", "{<redacted>}");
assertContains("gen/java/me/really/jose/v1/JoseOperationRequest.java", "JoseOperationRequest{<redacted>}");
assertContains("gen/java/me/really/jose/v1/JoseOperationResponse.java", "reallyMeHasUnknownFieldsForValidation");
for (const testName of [
  "knownAnswerAndTypedFailure",
  "jwsAndJwtRoundTripsUseCanonicalRoute",
  "unsignedJwtAndDirectJweRoundTrip",
  "oversizedManagedInputFailsBeforeJniCopy",
]) {
  assertContains("packages/kotlin/src/test/kotlin/me/really/jose/ReallyMeJoseTest.kt", testName);
}
assertContains("packages/kotlin/src/test/java/me/really/jose/ReallyMeJoseJavaTest.java", "typedFacadeIsUsableFromJava");
assertMarkdownContains("packages/kotlin/README.md", "owner-restricted directory");
assertMarkdownContains("packages/kotlin/README.md", "JVM cannot promise native-style erasure");
assertMarkdownContains("packages/kotlin/README.md", "Returned plaintext and claims arrays");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt",
  "responseBytes.fill(0)",
);
assertContains(".github/workflows/kotlin-ci.yml", "windows-2025");
assertContains(".github/workflows/kotlin-ci.yml", "verifyJarContainsNativeResources");
assertContains("packages/kotlin/build.gradle.kts", '"--profile", "release-ffi"');
assertContains("packages/kotlin/build.gradle.kts", 'environment.remove("CARGO_ENCODED_RUSTFLAGS")');
assertContains("packages/kotlin/build.gradle.kts", 'environment["RUSTFLAGS"] = ""');
assertContains("packages/kotlin/build.gradle.kts", "../../target/release-ffi/");
assertNotContains("packages/kotlin/build.gradle.kts", "-C panic=unwind");
assertContains("scripts/build_kotlin_native_resource.sh", "windows-x86_64");
assertContains("scripts/build_kotlin_native_resource.sh", "--profile release-ffi");
assertContains("scripts/build_kotlin_native_resource.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/build_kotlin_native_resource.sh", 'RUSTFLAGS=""');
assertContains("scripts/build_kotlin_native_resource.sh", "target/release-ffi/");
assertNotContains("scripts/build_kotlin_native_resource.sh", "-C panic=unwind");
assertContains("scripts/verify_native_artifact_handoff.mjs", "exact expected file set");
assertContains("scripts/verify_maven_release_repository.mjs", "Selected Maven publication artifacts");
assertContains("scripts/verify_maven_release_repository.mjs", "native manifest is not bound to the release source SHA");

assertContains("packages/kotlin-android/build.gradle.kts", 'id("com.android.library") version "9.5.2"');
assertContains("packages/kotlin-android/build.gradle.kts", 'val bouncyCastleToolVersion = "1.87"');
assertContains("packages/kotlin-android/build.gradle.kts", 'val commonsLangToolVersion = "3.22.0"');
assertContains("packages/kotlin-android/build.gradle.kts", 'val apacheHttpClientToolVersion = "4.5.14"');
assertContains("packages/kotlin-android/gradle.lockfile", "org.bouncycastle:bcprov-jdk18on:1.87=androidLintTool");
assertContains("packages/kotlin-android/gradle.lockfile", "org.apache.commons:commons-lang3:3.22.0=androidLintTool");
assertContains("packages/kotlin-android/gradle.lockfile", "org.apache.httpcomponents:httpclient:4.5.14=androidLintTool");
assertContains("packages/kotlin-android/build.gradle.kts", "compileSdk = 37");
assertContains("packages/kotlin-android/build.gradle.kts", "minCompileSdk = 37");
assertContains("packages/kotlin-android/build.gradle.kts", "minSdk = 24");
assertContains("packages/kotlin-android/consumer-r8-runtime/build.gradle.kts", "compileSdk = 37");
assertContains("packages/kotlin-android/consumer-r8-runtime/build.gradle.kts", "targetSdk = 37");
assertContains("packages/kotlin-android/build.gradle.kts", 'artifactId = "jose-android"');
assertContains("packages/kotlin-android/build.gradle.kts", "lockAllConfigurations()");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyAndroidNativeManifest(");
assertContains("packages/kotlin-android/build.gradle.kts", "JsonSlurper().parseText");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyElf64LoadAlignment");
assertContains("packages/kotlin-android/build.gradle.kts", "16_384L");
assertContains("packages/kotlin-android/build.gradle.kts", "ndkVersion = androidNdkVersion");
assertContains("packages/kotlin-android/build.gradle.kts", "release AAR JNI inventory does not match the frozen ABI matrix");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyReleaseAarContainsJniLibs");
assertNotContains("packages/kotlin-android/build.gradle.kts", "if (signingKeyValue != null)");
for (const abi of ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]) {
  assertContains("packages/kotlin-android/build.gradle.kts", `${abi}/libreallyme_jose_ffi.so`);
}
assertContains("packages/kotlin-android/consumer-rules.pro", "ReallyMeJoseNative");
assertContains("packages/kotlin-android/consumer-rules.pro", "me.really.jose.v1.**");
assertContains("packages/kotlin-android/consumer-r8-runtime/build.gradle.kts", "isMinifyEnabled = true");
assertContains("packages/kotlin-android/consumer-r8-runtime/src/main/java/me/really/jose/consumer/r8/ConsumerR8RuntimeActivity.java", "JWS_INVALID_SIGNATURE");
assertContains("packages/kotlin-android/consumer-r8-runtime/src/main/java/me/really/jose/consumer/r8/ConsumerR8RuntimeActivity.java", "encryptJwe");
assertContains("packages/kotlin-android/consumer-r8-runtime/src/main/java/me/really/jose/consumer/r8/ConsumerR8RuntimeActivity.java", "AndroidConformanceVectorRunner.run");
assertContains("packages/kotlin-android/consumer-r8-runtime/src/main/java/me/really/jose/consumer/r8/AndroidConformanceVectorRunner.java", 'runSuite(assets, "panva-jose.json"');
assertContains("packages/kotlin-android/consumer-r8-runtime/src/main/java/me/really/jose/consumer/r8/AndroidConformanceVectorRunner.java", "executeWireJsonRequest");
assertContains("packages/kotlin-android/consumer-r8-runtime/src/main/java/me/really/jose/consumer/r8/AndroidConformanceVectorRunner.java", "COMMON_MALFORMED_PROTOBUF");
assertContains("packages/kotlin/src/test/kotlin/me/really/jose/ConformanceVectorTest.kt", 'vectorCases("panva-jose.json")');
assertContains("packages/kotlin/src/test/kotlin/me/really/jose/ConformanceVectorTest.kt", "binaryAndProtoJsonWireRoutesAreByteIdentical");
assertContains("packages/kotlin/src/test/kotlin/me/really/jose/ConformanceVectorTest.kt", "COMMON_MALFORMED_JSON");
assertContains("packages/swift/Tests/ReallyMeJOSETests/ConformanceVectorTests.swift", 'vectorCases(named: "panva-jose.json")');
assertContains("packages/swift/Tests/ReallyMeJOSETests/ConformanceVectorTests.swift", "binaryAndProtoJSONWireRoutesAreByteIdentical");
assertContains("packages/swift/Tests/ReallyMeJOSETests/ConformanceVectorTests.swift", "commonMalformedJson");
assertContains("scripts/build_android_native_resources.sh", "aarch64-linux-android");
assertContains("scripts/build_android_native_resources.sh", "armv7-linux-androideabi");
assertContains("scripts/build_android_native_resources.sh", "x86_64-linux-android");
assertContains("scripts/build_android_native_resources.sh", "i686-linux-android");
assertContains("scripts/build_android_native_resources.sh", "--profile release-ffi");
assertContains("scripts/build_android_native_resources.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/build_android_native_resources.sh", 'RUSTFLAGS=""');
assertContains("scripts/build_android_native_resources.sh", "release-ffi/libreallyme_jose_ffi.so");
assertNotContains("scripts/build_android_native_resources.sh", "-C panic=unwind");
assertContains("scripts/build_android_native_resources.sh", "llvm-strip");
assertContains("scripts/write_native_manifest.mjs", 'package: "reallyme-jose-native"');
assertContains("scripts/write_native_manifest.mjs", "GITHUB_SHA does not match the checked-out source SHA");
assertContains("scripts/test-android-runtime.sh", "Android consumer R8 runtime gate passed");
assertContains("scripts/test_android_consumer_r8_runtime.sh", "app_installed");
assertContains("scripts/test_android_consumer_r8_runtime.sh", 'platforms;android-37.0');
assertContains("scripts/test_android_consumer_r8_runtime.sh", 'system-images;android-37.0;google_apis;x86_64');
assertContains("scripts/test_android_consumer_r8_runtime.sh", "-gpu swiftshader");
assertNotContains("scripts/test_android_consumer_r8_runtime.sh", "swiftshader_indirect");
assertContains("scripts/test_android_consumer_r8_runtime.sh", 'ANDROID_R8_DATA_PARTITION_MIB="4096"');
assertContains("scripts/test_android_consumer_r8_runtime.sh", '-partition-size "$ANDROID_R8_DATA_PARTITION_MIB"');
assertContains("scripts/test_android_consumer_r8_runtime.sh", "shell service check package");
assertContains("scripts/test_android_consumer_r8_runtime.sh", "Android package manager did not become available");
const androidRuntimeScript = readText("scripts/test_android_consumer_r8_runtime.sh");
if (
  androidRuntimeScript.indexOf(":consumer-r8-runtime:assembleRelease") >=
  androidRuntimeScript.indexOf('        -avd "$AVD_NAME"')
) {
  fail("Android runtime gate must build before starting the emulator");
}
if (
  androidRuntimeScript.indexOf("shell service check package") >=
  androidRuntimeScript.indexOf('"$ADB" install -r "$APK_PATH"')
) {
  fail("Android runtime gate must wait for the package manager before installation");
}
assertMarkdownContains("packages/kotlin-android/README.md", "API 24 or newer");
assertMarkdownContains("packages/kotlin-android/README.md", "minified consumer APK");
assertMarkdownContains("packages/kotlin-android/README.md", "16 KiB");
assertContains("packages/kotlin-android/gradlew", "../kotlin/gradlew");
assertContains("packages/kotlin-android/gradlew.bat", "..\\kotlin\\gradlew.bat");
assertNotContains("packages/kotlin-android/gradlew", 'cd "${SCRIPT_DIR}"');
assertNotContains("packages/kotlin-android/gradlew.bat", 'pushd "%SCRIPT_DIR%"');
assertMarkdownContains("vectors/README.md", "expected case counts");
const requirementTestNames = new Set(
  listFiles("crates")
    .filter((path) => path.endsWith(".rs"))
    .flatMap((path) => [...readText(path).matchAll(/\bfn\s+([A-Za-z0-9_]+)\s*\(/gu)]
      .map((match) => match[1])),
);
for (const requirement of readJson("vectors/requirements/jose.json")) {
  for (const name of [...requirement.positive_tests, ...requirement.negative_tests]) {
    if (!requirementTestNames.has(name)) {
      fail(`${requirement.id} names a missing test ${name}`);
    }
  }
}
for (const vectorId of [
  "reallyme-jwe/ecdh-es-p256-a128gcm-deflate",
  "reallyme-jwe/ecdh-es-p256-a128gcm-deflate-tampered-tag",
  "reallyme-jwe/ecdh-es-p256-a128gcm-deflate-oversize",
  "reallyme-jwe/ecdh-es-p384-a192gcm-deflate",
  "reallyme-jwe/ecdh-es-p521-a256gcm-deflate",
  "reallyme-jwe/ecdh-es-p384-a192gcm-deflate-tampered-tag",
  "reallyme-jwe/ecdh-es-p256-a128gcm-unsupported-gzip",
  "reallyme-jwe/ecdh-es-p521-a256gcm-deflate-oversize",
]) {
  assertContains("vectors/jwe-compact.json", vectorId);
}
assertContains(".github/workflows/android-ci.yml", "ndk;30.0.16248370");
assertContains(".github/workflows/android-ci.yml", "scripts/run-android-emulator.sh");
assertContains("scripts/run-android-emulator.sh", "scripts/test-android-runtime.sh");
assertContains(".github/workflows/android-ci.yml", "scripts/stage-android-publication.sh");
assertContains(".github/workflows/android-ci.yml", "scripts/prepare-android-runtime.sh");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "linux-aarch64");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "verify_maven_release_repository.mjs");
assertContains(
  ".github/workflows/kotlin-android-package-preflight.yml",
  `${releaseReadinessCommand} --policy-only`,
);
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "kotlin-digest-${{ matrix.platform }}");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "build/kotlin-native-digests");
assertNotContains(".github/workflows/kotlin-android-package-preflight.yml", "needs.jvm-native.outputs");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "Download tested Android publication");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "verify-publication");
assertNotContains(".github/workflows/kotlin-android-package-preflight.yml", "scripts/build_android_native_resources.sh");
for (const boundary of [
  "MAVEN_SIGNING_KEY_ID",
  "MAVEN_SIGNING_PASSWORD",
  "kotlin-android-package-preflight.yml",
  "kotlin-native-*",
  "kotlin-digest-*",
  "verify_native_artifact_handoff.mjs",
  "verify_sdk_release_version.mjs",
  "verify_maven_release_repository.mjs",
  "publishMavenPublicationToLocalReleaseRepository",
  "publishReleasePublicationToLocalReleaseRepository",
  "reallyme-maven-central-${VERSION}.zip",
]) {
  assertContains("scripts/maven-central-bundle.local.sh", boundary);
}
assertContains("README.md", "scripts/maven-central-bundle.local.sh");
assertContains(".github/workflows/kotlin-android-package-release.yml", "Download verified package");
assertContains(".github/workflows/kotlin-android-package-release.yml", "sign_maven_release_repository.mjs");
assertContains(".github/workflows/kotlin-android-package-release.yml", "promote_maven_release_repository.mjs");
assertNotContains(".github/workflows/kotlin-android-package-release.yml", "publish-jvm:");
assertNotContains(".github/workflows/kotlin-android-package-release.yml", "publish-android:");
assertContains("scripts/promote_maven_release_repository.mjs", '"If-None-Match": "*"');
assertContains("scripts/promote_maven_release_repository.mjs", "release-version-already-exists");
assertContains("scripts/promote_maven_release_repository.mjs", "remote-byte-verification-failed");
assertContains("scripts/promote_maven_release_repository.mjs", "partial-release-rollback-failed");
assertContains("scripts/collect_maven_release_files.mjs", "requireExactInventory");
assertContains("scripts/sign_maven_release_repository.mjs", "artifact-signature-verification-failed");
assertContains("scripts/sign_maven_release_repository.mjs", '"--verify"');
assertWorkflowPermissionsPolicy({
  path: ".github/workflows/kotlin-android-package-release.yml",
  workflow: { contents: "read" },
  jobs: {
    "verify-release-sha": { actions: "read", contents: "read" },
    "publish-maven": { actions: "read", contents: "read" },
  },
});
assertContains("scripts/verify_sdk_release_version.mjs", "Rust, Swift, JVM, Android, and TypeScript package versions");
assertContains(".github/workflows/crates-package-preflight.yml", "scripts/verify_sdk_release_version.test.mjs");
assertContains(".github/workflows/crates-package-preflight.yml", "scripts/publish_crates_in_order.test.mjs");
assertContains(".github/workflows/swift-package-preflight.yml", "scripts/verify_sdk_release_version.test.mjs");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "scripts/verify_sdk_release_version.test.mjs");

for (const file of listFiles("crates/ffi/src").filter((path) => path.endsWith(".rs"))) {
  if (file === "crates/ffi/src/generated_contract/jose_ffi_status_tests.rs") {
    assertContains("crates/ffi/src/generated_contract/jose_ffi_status.rs", '#[cfg(test)]\n#[path = "jose_ffi_status_tests.rs"]\nmod tests;');
    continue;
  }
  if (file === "crates/ffi/src/guard_tests.rs") {
    assertContains("crates/ffi/src/lib.rs", "#[cfg(test)]\nmod guard_tests;");
    continue;
  }
  const source = readText(file);
  if (source.split("\n").length > 500) {
    fail(`${file} exceeds the production source line limit`);
  }
  if (/#\[cfg\(test\)\]\s*mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/u.test(source)) {
    fail(`${file} contains an inline test module`);
  }
  for (const forbidden of [
    "unwrap(",
    "expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!(",
    "dbg!(",
    "println!(",
  ]) {
    if (source.includes(forbidden)) {
      fail(`${file} contains forbidden production token ${forbidden}`);
    }
  }
  if (/Result<[^>\n]+,\s*(String|&str|\(\))/.test(source)) {
    fail(`${file} contains an untyped Result error`);
  }
}

const schemaSelectorTestModules = [
  "jose_operation_kind", "jose_wire_error_branch", "jwe_compression_algorithm",
  "jwe_content_encryption_algorithm", "jwe_key_management_algorithm", "jwe_key_management_suite",
  "jws_algorithm", "jwt_algorithm", "jwt_registered_claim", "jwt_temporal_claim", "policy_defaults",
];
for (const module of schemaSelectorTestModules) {
  assertContains(`crates/jose/src/generated_contract/${module}.rs`,
    `#[cfg(test)]\n#[path = "${module}_tests.rs"]\nmod tests;`);
}
const explicitlyTestOnlyRustFiles = new Set([
  ...schemaSelectorTestModules.map((module) => `crates/jose/src/generated_contract/${module}_tests.rs`),
  "crates/jose/src/measure_encoding_tests.rs",
  "crates/jose/src/operation_contract/jws/verify_tests.rs",
]);
assertContains("crates/jose/src/lib.rs", "#[cfg(test)]\nmod measure_encoding_tests;");
assertContains(
  "crates/jose/src/operation_contract/jws/mod.rs",
  "#[cfg(test)]\nmod verify_tests;",
);
for (const file of listFiles("crates/jose/src").filter((path) => path.endsWith(".rs"))) {
  if (explicitlyTestOnlyRustFiles.has(file)) {
    continue;
  }
  const source = readText(file);
  if (source.split("\n").length > 500) {
    fail(`${file} exceeds the production source line limit`);
  }
  if (/#\[cfg\(test\)\]\s*mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/u.test(source)) {
    fail(`${file} contains an inline test module`);
  }
  if (source.includes("pub use ") && source.includes("::*")) {
    fail(`${file} contains a wildcard re-export`);
  }
  if (source.includes("use ") && source.includes("::*")) {
    fail(`${file} contains a wildcard import`);
  }
  for (const forbidden of [
    "unwrap(",
    "expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!(",
    "dbg!(",
    "println!(",
  ]) {
    if (source.includes(forbidden)) {
      fail(`${file} contains forbidden production token ${forbidden}`);
    }
  }
  if (/Result<[^>\n]+,\s*(String|&str|\(\))/.test(source)) {
    fail(`${file} contains an untyped Result error`);
  }
  if (/type\s+Err\s*=\s*\(\)/.test(source)) {
    fail(`${file} contains type Err = ()`);
  }
}

for (const stale of [
  "crates/jose/src/jwe/compact.rs",
  "crates/jose/src/jwe/header.rs",
  "crates/jose/src/jwe/kdf.rs",
  "crates/jose/src/jws/compact.rs",
  "crates/jose/src/jws/header.rs",
  "crates/jose/src/jwt/compact.rs",
  "crates/jose/src/jwt/header.rs",
]) {
  if (listFiles("crates/jose/src").includes(stale)) {
    fail(`${stale} should remain split into verb-named implementation files`);
  }
}

const requiredWorkflows = [
  ".github/workflows/ci.yml",
  ".github/workflows/cla.yaml",
  ".github/workflows/rust-ci.yml",
  ".github/workflows/fuzz-ci.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/readiness.yml",
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/swift-ci.yml",
  ".github/workflows/kotlin-ci.yml",
  ".github/workflows/android-ci.yml",
  ".github/workflows/swift-package-preflight.yml",
  ".github/workflows/swift-package-release.yml",
  ".github/workflows/kotlin-android-package-preflight.yml",
  ".github/workflows/kotlin-android-package-release.yml",
  ".github/workflows/npm-package-preflight.yml",
  ".github/workflows/npm-package-release.yml",
];
const spdxCopyright = ["SPDX-FileCopyrightText:", "2026 ReallyMe Technologies Limited"].join(" ");
const spdxLicense = ["SPDX-License-Identifier:", "MIT OR Apache-2.0"].join(" ");
for (const workflow of requiredWorkflows) {
  assertRawContains(workflow, spdxCopyright, "the SPDX copyright identifier");
  assertRawContains(workflow, spdxLicense, "the SPDX license identifier");
}

const immutableVendoredSpdxPaths = new Set([".github/workflows/cla.yaml"]);
// Generated by the checksum-verified Gradle distribution. Keep upstream
// licensing intact and pin the launcher contents rather than relabeling them.
const vendoredLauncherDigests = new Map([
  ["packages/kotlin/gradlew", "a5a5c199ba02189ae8c46a334223371a20599d9c298ef65e7540ede4a3f72d59"],
  ["packages/kotlin/gradlew.bat", "31ec098bd961c460b62875950c3eff5c8213bcb0bbde38d769b88512877fd21f"],
]);
const spdxTextPath = /\.(?:c|dict|h|java|js|kt|kts|mjs|modulemap|plist|pro|properties|proto|rs|sh|swift|ts|xml|ya?ml)$/u;
const spdxTextNames = new Set([".gitignore", "NOTICE", "Package.swift", "gradlew", "gradlew.bat"]);

for (const path of loadTrackedFiles()) {
  if (path.endsWith(".md") || path.endsWith(".txt")) {
    assertNotContains(path, "SPDX-FileCopyrightText:");
    assertNotContains(path, "SPDX-License-Identifier:");
    continue;
  }
  if (vendoredLauncherDigests.has(path)) {
    const digest = createHash("sha256").update(readText(path).replaceAll("\r\n", "\n")).digest("hex");
    if (digest !== vendoredLauncherDigests.get(path)) fail(`${path} differs from the reviewed Gradle launcher`);
    continue;
  }
  if (immutableVendoredSpdxPaths.has(path)) {
    // The upstream runner verifies this file byte-for-byte against the pinned
    // release, so its upstream-owned header cannot be rewritten locally.
    continue;
  }
  const name = path.split("/").at(-1);
  if (!spdxTextPath.test(path) && !spdxTextNames.has(name)) continue;

  const text = readText(path);
  const hasCopyright = text.includes("SPDX-FileCopyrightText:");
  const hasLicense = text.includes("SPDX-License-Identifier:");
  if (!hasCopyright && !hasLicense) continue;
  if (!text.includes(spdxCopyright) || !text.includes(spdxLicense)) {
    fail(`${path} has an incomplete or stale SPDX header`);
  }
  if (text.split(spdxCopyright).length !== 2 || text.split(spdxLicense).length !== 2) {
    fail(`${path} must contain exactly one normalized SPDX header`);
  }
}

const fuzzCargo = readText("fuzz/Cargo.toml");
for (const target of [
  "compact_jwe",
  "compact_jwe_ecdh_es",
  "parse_jwe_header",
  "compact_jws_es256",
  "signed_jwt",
  "validate_jwt_temporal",
  "unsigned_jwt",
  "operation_wire",
  "operation_response",
  "ffi_operation",
]) {
  assertContains("fuzz/Cargo.toml", `name = "${target}"`);
  assertContains(".github/workflows/fuzz.yml", `- ${target}`);
}
assertContains(".github/workflows/fuzz-ci.yml", "workflow_call:");
assertContains(".github/workflows/fuzz.yml", "schedule:");
assertContains(".github/workflows/fuzz.yml", "github.event_name == 'schedule'");
assertContains(".github/workflows/fuzz.yml", "nightly-2026-09-15");
assertMarkdownContains("fuzz/README.md", "nightly-2026-09-15");
assertNotContains("fuzz/README.md", "nightly-2026-07-01");
assertNotContains(".github/workflows/fuzz.yml", "toolchain: nightly\n");
assertContains(".github/workflows/fuzz.yml", "CARGO_FUZZ_VERSION: 0.13.2");
assertContains(".github/workflows/fuzz.yml", "FUZZ_MAX_TOTAL_TIME_SECONDS: 900");
for (const path of [".github/workflows/fuzz-ci.yml", ".github/workflows/fuzz.yml"]) {
  assertContains(path, "cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1");
}
assertContains(".github/workflows/fuzz-ci.yml", "git diff --exit-code -- fuzz/Cargo.lock");
assertContains(".github/workflows/fuzz.yml", "Restore and persist fuzz corpus");
assertContains(".github/workflows/fuzz.yml", "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9");
assertContains(
  ".github/workflows/fuzz.yml",
  "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
);
assertNotContains(
  ".github/workflows/fuzz.yml",
  "actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4",
);
assertMarkdownContains("fuzz/README.md", "`compact_jwe_ecdh_es`");
assertMarkdownContains("fuzz/README.md", "`parse_jwe_header`");
assertMarkdownContains("fuzz/README.md", "`validate_jwt_temporal`");
assertMarkdownContains("fuzz/README.md", "`operation_wire`");
assertMarkdownContains("fuzz/README.md", "`operation_response`");
assertMarkdownContains("fuzz/README.md", "`ffi_operation`");
assertMarkdownContains("fuzz/README.md", "Run targets from the repository root.");
assertMarkdownContains("fuzz/README.md", "fuzz/dictionaries/jose.dict");
assertContains("fuzz/fuzz_targets/operation_wire.rs", "execute_operation_v1");
assertContains("fuzz/fuzz_targets/operation_wire.rs", "execute_operation_json_v1");
assertContains(
  "fuzz/fuzz_targets/operation_response.rs",
  "decode_operation_response_v1",
);
assertContains("fuzz/fuzz_targets/ffi_operation.rs", "rm_jose_execute_operation_v1");
assertContains("fuzz/fuzz_targets/compact_jwe_ecdh_es.rs", "P256EcdhEsJweKeyResolver");
assertContains("fuzz/fuzz_targets/parse_jwe_header.rs", "CompactJweProtectedHeader");
assertContains(
  "fuzz/fuzz_targets/validate_jwt_temporal.rs",
  "decode_verify_jwt_with_claims_validation",
);
assertContains("fuzz/dictionaries/jose.dict", "ECDH-ES");
for (const seed of [
  "fuzz/corpus/compact_jwe/direct-a128gcm",
  "fuzz/corpus/compact_jwe_ecdh_es/p256-a128gcm",
  "fuzz/corpus/parse_jwe_header/direct-valid",
  "fuzz/corpus/compact_jws_es256/es256-valid",
  "fuzz/corpus/signed_jwt/es256-valid",
  "fuzz/corpus/validate_jwt_temporal/boundaries",
  "fuzz/corpus/unsigned_jwt/none-valid",
  "fuzz/corpus/operation_wire/json-missing-operation",
  "fuzz/corpus/operation_wire/json-canonical-missing-operation",
  "fuzz/corpus/operation_wire/json-duplicate-operation",
  "fuzz/corpus/operation_response/valid-jws-verify-v1-hex",
  "fuzz/corpus/ffi_operation/json-missing-operation",
]) {
  if (!listFiles("fuzz/corpus").includes(seed)) {
    fail(`${seed} is missing from the fuzz seed corpus`);
  }
}
assertContains("tools/vector-audit/src/cases.rs", "decrypt_jwe_with_cek(case, compact, &derived_cek)");
assertContains("tools/vector-audit/src/cases.rs", "assert_expected_plaintext(case, &plaintext)");
assertContains("tools/panva-goldens/generate.mjs", "function cekLengthBits(enc)");
assertContains("tools/panva-goldens/generate.mjs", "const keyDataLenBits = cekLengthBits");
assertContains(".gitignore", "!packages/ts/src/proto/generated/");
assertContains(".gitignore", "!packages/ts/src/proto/generated/**");
assertNotContains(".gitignore", "packages/ts/wasm/");
assertContains(".gitignore", "\nAGENTS.md\n");
assertContains(".github/workflows/readiness.yml", releaseReadinessCommand);
for (const directory of [
  "crates/jose/tests",
  "crates/proto/tests",
  "crates/ffi/tests",
  "packages/swift/Tests",
  "packages/kotlin/src/test",
  "packages/ts/test",
]) {
  for (const path of listFiles(directory)) {
    if (!/\.(?:rs|swift|kt|mjs)$/u.test(path)) continue;
    if (/#\[ignore(?:\s|\]|\()/u.test(readText(path))
        || /@Disabled\b/u.test(readText(path))
        || /\.(?:disabled|skip|todo|only)\s*\(/u.test(readText(path))) {
      fail(`${path} contains a disabled or exclusive test`);
    }
  }
}
for (const workflow of [
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/protobuf-ci.yml",
  ".github/workflows/readiness.yml",
  ".github/workflows/rust-ci.yml",
  ".github/workflows/swift-ci.yml",
  ".github/workflows/npm-package-preflight.yml",
  ".github/workflows/npm-package-release.yml",
]) {
  assertContains(workflow, "persist-credentials: false");
}
assertContains("scripts/publish_crates_in_order.mjs", "const fetchArgs =");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  "CARGO_TARGET_DIR: inspectionTargetDirectory",
);
assertContains(
  "scripts/publish_crates_in_order.mjs",
  '"--all-features",\n    "--locked",\n    "--offline"',
);
assertContains(
  "scripts/publish_crates_in_order.mjs",
  '"--dry-run",\n    "--no-verify",\n    "--locked"',
);
for (const workflow of [
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/rust-ci.yml",
]) {
  assertContains(workflow, "CARGO_HOME: ${{ runner.temp }}/package-preflight-cargo-home");
}

const pinnedBufDigest =
  "BUF_LINUX_X86_64_SHA256: fad1e38d6909bbb583a4da81d8c02a01046e2cd663bde7e337dd24277393764b";
for (const workflow of [
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/protobuf-ci.yml",
]) {
  assertContains(workflow, "BUF_VERSION: 1.75.0");
  assertContains(workflow, pinnedBufDigest);
  assertContains(workflow, "--proto '=https' --tlsv1.2");
  assertContains(workflow, "sha256sum --check --strict");
  assertNotContains(workflow, "bufbuild/buf-setup-action@");
}

const setupNodeAction =
  "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0";
const expectedNodeSetupCounts = new Map([
  [".github/workflows/crates-package-preflight.yml", 2],
  [".github/workflows/crates-release.yml", 2],
  [".github/workflows/protobuf-ci.yml", 1],
  [".github/workflows/readiness.yml", 1],
  [".github/workflows/rust-ci.yml", 1],
]);
const nodeCommandPattern =
  /^\s*(?:run:\s*)?(?:node|npm|npx|pnpm|yarn|corepack)(?:\s|$)/mu;
for (const workflow of listFiles(".github/workflows").filter(
  (path) => path.endsWith(".yml") || path.endsWith(".yaml"),
)) {
  const source = readText(workflow);
  const setupCount = source.split(setupNodeAction).length - 1;
  const node26Count = source.split("node-version: '26'").length - 1;
  const configuredNodeVersionCount = source.split("node-version:").length - 1;
  if (nodeCommandPattern.test(source) && setupCount === 0) {
    fail(`${workflow} invokes Node tooling without pinned actions/setup-node`);
  }
  if (source.includes("actions/setup-node@") && setupCount === 0) {
    fail(`${workflow} uses an unapproved actions/setup-node revision`);
  }
  if (node26Count !== setupCount || configuredNodeVersionCount !== setupCount) {
    fail(`${workflow} must configure Node 26 for every setup-node step`);
  }
  const expectedCount = expectedNodeSetupCounts.get(workflow);
  if (expectedCount !== undefined && setupCount !== expectedCount) {
    fail(`${workflow} must contain ${expectedCount} pinned Node 26 setup step(s)`);
  }
}
if (!rootCargo.includes("[workspace.lints.clippy]")) {
  fail("workspace clippy lint policy is missing");
}

assertRustSourcePolicy({
  roots: ["."],
  generatedPrefixes: ["crates/proto/src/generated"],
});
assertTypeScriptSourcePolicy({
  roots: ["packages/ts/src"],
  generatedPrefixes: ["packages/ts/src/proto/generated"],
  tsconfigPaths: ["packages/ts/tsconfig.json"],
  staticAnalysis: {
    files: [{
      path: "packages/ts/tsconfig.json",
      required: [
        '"noImplicitReturns": true',
        '"noUnusedLocals": true',
        '"noUnusedParameters": true',
        '"noFallthroughCasesInSwitch": true',
      ],
    }],
  },
  verification: sourceVerification([
    {
      roles: ["typecheck", "lint"],
      command: "npm",
      args: ["--prefix", "packages/ts", "run", "typecheck"],
    },
    {
      roles: ["test"],
      command: "npm",
      args: ["--prefix", "packages/ts", "test"],
    },
  ]),
});
assertSwiftSourcePolicy({
  roots: ["packages/swift/Sources", "packages/swift/Tests"],
  generatedPrefixes: ["gen/swift"],
  configuration: {
    files: [{
      path: "scripts/check_release_readiness.mjs",
      required: ["-strict-concurrency=complete", "-warnings-as-errors"],
    }],
  },
  verification: sourceVerification([
    {
      roles: ["format", "lint"],
      command: "swift",
      args: [
        "format",
        "lint",
        "--recursive",
        "--strict",
        "packages/swift/Sources/ReallyMeJOSE",
        "packages/swift/Tests/ReallyMeJOSETests",
      ],
    },
    {
      roles: ["build", "test"],
      command: "scripts/test_swift_source_tree.sh",
      args: [],
    },
  ]),
});
assertKotlinSourcePolicy({
  roots: ["packages/kotlin/src"],
  generatedPrefixes: ["gen/kotlin"],
  configuration: {
    files: [{
      path: "packages/kotlin/build.gradle.kts",
      required: ["explicitApi()", "allWarningsAsErrors.set(true)"],
    }],
  },
  verification: sourceVerification([{
    roles: ["format", "static-analysis", "compile", "test"],
    command: "packages/kotlin/gradlew",
    args: ["-p", "packages/kotlin", "--no-daemon", "test"],
  }]),
});

if (!policyOnlyMode) {
  run(process.execPath, ["--test", "scripts/tests/operation-contract-readiness.test.mjs"]);
  run(process.execPath, ["--test", "scripts/tests/shell-tools.test.mjs"]);
  run("cargo", ["fmt", "--manifest-path", "tools/vector-audit/Cargo.toml", "--check"]);
  run("cargo", [
    "clippy",
    "--locked",
    "--manifest-path",
    "tools/vector-audit/Cargo.toml",
    "--all-targets",
    "--",
    "-D",
    "warnings",
  ]);
  run("cargo", ["run", "--locked", "--manifest-path", "tools/vector-audit/Cargo.toml", "--", "."]);
}

console.log(`release readiness ${policyOnlyMode ? "policy " : ""}ok`);
