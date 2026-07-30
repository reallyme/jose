#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createReleaseReadinessContext } from "./release-readiness/core.mjs";
import { assertOperationContractArchitecture } from "./operation-contract-readiness.mjs";

const {
  readText,
  readJson,
  listFiles,
  fail,
  assertContains,
  assertNotContains,
  assertNotMatches,
  assertLockPackageVersion,
  run,
  assertNodeWorkflowJobsPinNode,
  assertProtoContract,
  assertReallyMeProtobufReleasePolicy,
  assertReallyMeVendoredCorePolicy,
  assertWorkflowActionsPinned,
  assertCargoFuzzWorkflowPolicy,
  assertWorkflowPermissionsPolicy,
  runNodeCheck,
} = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

assertReallyMeVendoredCorePolicy();
assertWorkflowActionsPinned();
assertCargoFuzzWorkflowPolicy({ version: "0.13.2" });
assertOperationContractArchitecture({ readText, listFiles, fail });
runNodeCheck("scripts/prepare_semver_baseline.test.mjs");

const crateVersion = "0.3.0";
const protoCrateVersion = "0.3.0";
const buffaVersion = "0.9.1";
const cryptoVersion = "0.3.4";
const localCryptoVersion = "0.3.4";
const codecVersion = "0.2.1";
const npmPackageVersion = "0.3.0";
const rustSemverBaselineCommit = "66d54835235c414051009523670afb6bb3e51007";
const releaseReadinessCommit = "44065b7488a8d3c77f66f530dff770fb39be9707";
const releaseReadinessCommand = "node .release-readiness/scripts/run-consumer-check.mjs";
const releaseReadinessCheckoutRequired = [
  "repository: reallyme/release-readiness",
  `ref: ${releaseReadinessCommit}`,
  "path: .release-readiness",
];
const allowLocalCryptoAudit = process.env.REALLYME_JOSE_ALLOW_LOCAL_CRYPTO_AUDIT === "1";
const allowLocalCodecAudit = process.env.REALLYME_JOSE_ALLOW_LOCAL_CODEC_AUDIT === "1";
const generatedFreshnessMode = process.argv.includes("--generated-freshness");
const policyOnlyMode = process.argv.includes("--policy-only");
const releasePackagesMode = process.argv.includes("--release-packages");

if (releasePackagesMode && process.env.RELEASE_VERSION !== crateVersion) {
  fail("RELEASE_VERSION must match every 0.3.0 release package");
}

assertNodeWorkflowJobsPinNode({ nodeVersion: "24" });

const rootCargo = readText("Cargo.toml");
assertContains("Cargo.toml", 'members = ["crates/jose", "crates/ffi", "crates/proto", "crates/wasm"]');
assertContains("Cargo.toml", 'exclude = ["fuzz"]');
assertContains("Cargo.toml", "overflow-checks = true");
assertContains("Cargo.toml", "[profile.release-ffi]");
assertContains("Cargo.toml", 'inherits = "release"');
assertContains("Cargo.toml", 'panic = "unwind"');
assertContains("Cargo.toml", `buffa = { version = "${buffaVersion}", features = ["json"] }`);
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
if (allowLocalCodecAudit) {
  assertContains(
    "Cargo.toml",
    `reallyme-codec = { version = "${codecVersion}", path = "../codec/crates/codec", default-features = false }`,
  );
} else {
  assertContains(
    "Cargo.toml",
    `reallyme-codec = { version = "${codecVersion}", default-features = false }`,
  );
}
assertContains(
  "Cargo.toml",
  `reallyme-jose-proto = { version = "${protoCrateVersion}", path = "crates/proto", default-features = false }`,
);
if (allowLocalCryptoAudit) {
  assertContains(
    "Cargo.toml",
    `reallyme-crypto = { version = "${localCryptoVersion}", path = "../crypto", default-features = false }`,
  );
  assertContains(
    "fuzz/Cargo.toml",
    `reallyme-crypto = { version = "${localCryptoVersion}", path = "../../crypto", default-features = false, features = ["jwk"] }`,
  );
} else {
  assertContains(
    "Cargo.toml",
    `reallyme-crypto = { version = "${cryptoVersion}", default-features = false }`,
  );
  assertContains(
    "fuzz/Cargo.toml",
    `reallyme-crypto = { version = "${cryptoVersion}", default-features = false, features = ["jwk"] }`,
  );
}
if (!allowLocalCodecAudit) {
  assertNotContains("Cargo.toml", "reallyme-codec = { path");
}
if (!allowLocalCryptoAudit) {
  assertNotContains("Cargo.toml", "reallyme-crypto = { path");
}
assertNotContains("Cargo.toml", 'time = "');

const ffiCargo = readText("crates/ffi/Cargo.toml");
assertContains("crates/ffi/Cargo.toml", 'name = "reallyme-jose-ffi"');
assertContains("crates/ffi/Cargo.toml", 'version = "0.3.0"');
assertContains("crates/ffi/Cargo.toml", "publish = false");
assertContains("crates/ffi/Cargo.toml", 'crate-type = ["rlib", "staticlib", "cdylib"]');
assertContains("crates/ffi/Cargo.toml", 'default = ["native"]');
assertContains(
  "crates/ffi/Cargo.toml",
  'native = ["reallyme-crypto/native", "reallyme-jose/native"]',
);
assertContains("crates/ffi/Cargo.toml", 'features = ["csprng"]');
assertContains(
  "crates/ffi/Cargo.toml",
  'reallyme-jose = { version = "0.3.0", path = "../jose", default-features = false, features = ["wire"] }',
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
assertContains("crates/proto/Cargo.toml", 'generated = ["dep:buffa", "buffa/json", "dep:serde", "dep:zeroize"]');
assertContains("crates/proto/Cargo.toml", 'default = ["generated"]');
assertContains(
  "crates/proto/Cargo.toml",
  'documentation = "https://docs.rs/reallyme-jose-proto"',
);
assertContains("crates/proto/Cargo.toml", "[package.metadata.docs.rs]");
assertContains("crates/proto/Cargo.toml", "all-features = true");
assertContains("crates/proto/Cargo.toml", '"/tests/**/*.rs"');
assertContains("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
assertContains(
  "crates/proto/README.md",
  'reallyme-jose-proto = { version = "0.3.0", features = ["generated"] }',
);
assertContains("crates/proto/README.md", "JoseOperationRequest");
assertContains("crates/proto/README.md", "JoseOperationResponse");
assertContains("crates/proto/README.md", "operation-discriminated response");
assertContains("crates/proto/README.md", "Copyright © 2026 by ReallyMe LLC.");
assertContains("crates/proto/NOTICE", "ReallyMe JOSE Proto");
assertContains(
  "crates/proto/src/generated.rs",
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
assertContains("packages/ts/package.json", '"@bufbuild/protobuf": "2.12.1"');
assertContains("packages/ts/package-lock.json", '"name": "@reallyme/jose"');
assertContains("packages/ts/package-lock.json", '"version": "0.3.0"');
assertContains("packages/ts/tsconfig.json", '"strict": true');
assertContains("packages/ts/tsconfig.json", '"noUnusedLocals": true');
assertContains("packages/ts/tsconfig.json", '"noUnusedParameters": true');
assertContains("packages/ts/README.md", "## Raw WASM Module Contract");
assertContains("packages/ts/README.md", "Direct raw WASM calls are unsupported");
assertContains("packages/ts/src/errors.ts", "class ReallyMeJoseError extends Error");
assertContains("packages/ts/src/provider.ts", "installReallyMeJoseWasmProvider");
assertContains("packages/ts/src/facade.ts", "export const ReallyMeJose = Object.freeze");
assertContains("packages/ts/scripts/build-wasm.mjs", 'const REQUIRED_WASM_PACK_VERSION = "0.15.0"');
assertContains("packages/ts/scripts/build-wasm.mjs", 'const REQUIRED_WASM_BINDGEN_VERSION = "0.2.126"');
assertContains("packages/ts/scripts/check-pack.mjs", "unreviewed semantic export");
assertContains("packages/ts/test/vector-conformance.test.mjs", "all 96 cross-lane conformance vectors");
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

assertContains("crates/jose/src/lib.rs", "pub use reallyme_crypto::{core::Algorithm, csprng::SecureRandom, jwk::Jwk, signer::Signer};");
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
  "crates/jose/src/jwe/validate_header/algorithms.rs",
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
assertContains("crates/jose/src/jwt/verify.rs", "const ED25519_SIGNATURE_LEN: usize = 64;");
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
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "ES256K is supported by JWT through JWK algorithm binding",
);
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "reserved 1 to 3;");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", 'reserved "JOSE_SIGNATURE_ALGORITHM_ES256K";');
assertNotContains("crates/jose/src/wire.rs", "JOSE_SIGNATURE_ALGORITHM_ES256K");
assertNotContains("crates/jose/src/lib.rs", "#![allow(missing_docs)]");

const lock = readText("Cargo.lock");
const cratesIo = "registry+https://github.com/rust-lang/crates.io-index";
if (allowLocalCodecAudit) {
  assertLockPackageVersion(lock, "reallyme-codec", codecVersion);
} else {
  assertLockPackageVersion(lock, "reallyme-codec", codecVersion, cratesIo);
}
if (allowLocalCryptoAudit) {
  assertLockPackageVersion(lock, "reallyme-crypto", localCryptoVersion);
} else {
  assertLockPackageVersion(lock, "reallyme-crypto", cryptoVersion, cratesIo);
}
assertLockPackageVersion(lock, "reallyme-jose-proto", protoCrateVersion);

assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
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
assertContains("README.md", "wire` feature is opt-in");
assertContains("README.md", "Owned wire output buffers use `Zeroizing<Vec<u8>>`");
assertContains("README.md", "Decode `JoseOperationResponse`");
assertContains("README.md", "only executable wire surface");
assertContains("README.md", "With the `wire` feature enabled");
assertContains("README.md", "prefer the native `jws`, `jwt`, and `jwe` modules");
assertContains("README.md", "does not define an RPC service, transport, endpoint");
assertContains("README.md", "a new minor release may intentionally change the schema");
assertContains("README.md", "Unsigned JWT decoding is parsing only");
assertContains("README.md", "JWT wire header policy is presence-sensitive");
assertContains("README.md", "JWT wire temporal validation is explicit");
assertContains("README.md", "JWE decrypt requests can carry a presence-sensitive protected-header policy");
assertContains("README.md", "`temporal_policy.now_unix`");
assertContains("README.md", "also rejects any message whose protobuf encoding");
assertContains("README.md", "release-readiness workflow runs for documentation-only");
assertContains("README.md", "Independent Vector Audit");
assertContains("README.md", "ES256 verification accepts both low-S and high-S ECDSA signatures");
assertContains("README.md", "Face ID and Secure");
assertContains("README.md", "challenge, nonce, `jti`, payload");
assertContains("README.md", "Those deserialized values are not zeroizing owners");
assertContains("README.md", "wasm feature lane uses package-owned Rust cryptographic implementations");
assertContains("crates/jose/README.md", "## Operation Execution Boundary");
assertContains("crates/jose/README.md", "Owned wire outputs use zeroizing buffers");
assertContains("crates/jose/README.md", "Treat that dependency as the adapter ABI");
assertContains("crates/jose/README.md", "does not authenticate the sender");
assertContains("crates/jose/README.md", "optional `wire` feature");
assertContains("crates/jose/README.md", "native SDK users do not compile Buffa");
assertContains("crates/jose/README.md", "With the `wire` feature enabled");
assertContains("crates/jose/README.md", "execute_operation_json_v1");
assertContains("crates/jose/README.md", "only executable wire contract");
assertContains("crates/jose/README.md", "verified claims JSON also reject duplicate object");
assertContains("crates/jose/README.md", "accepts otherwise valid high-S signatures");
assertContains("crates/jose/README.md", "Face ID and Secure Enclave protected");
assertContains("crates/jose/README.md", "zeroize on drop");
assertContains("crates/jose/README.md", "wasm lane uses package-owned Rust cryptographic implementations");
assertContains("crates/jose/README.md", "JWT wire header policy is presence-sensitive");
assertContains("crates/jose/README.md", "JWT wire temporal validation is also explicit");
assertContains("crates/jose/README.md", "JWE decrypt requests expose the native protected-header policy");
assertContains("crates/jose/README.md", "large binary payloads are more efficient through the binary protobuf lane");
assertContains("crates/proto/README.md", "It defines messages only");
assertContains("crates/proto/README.md", "protobuf `service`, network transport");
assertContains("crates/proto/README.md", "The intended adapter flow is");
assertContains("crates/proto/README.md", "`JoseOperationResponse` as the canonical versioned response");
assertContains("crates/proto/README.md", "canonical results remain binary protobuf");
assertContains("crates/proto/README.md", "JWE decrypt requests include a presence-sensitive");
assertContains("crates/proto/README.md", "Pre-1.0");
for (const readme of ["README.md", "crates/jose/README.md", "vectors/README.md", "fuzz/README.md"]) {
  assertContains(readme, "Copyright © 2026 by ReallyMe LLC.");
  assertContains(readme, "ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.");
}
assertContains("README.md", "See [LICENSE](LICENSE) and");
assertContains("README.md", "[NOTICE](NOTICE).");
assertContains("crates/jose/README.md", "See [LICENSE](LICENSE) and");
assertContains("crates/jose/README.md", "[NOTICE](NOTICE).");
assertContains("vectors/README.md", "See [LICENSE](../LICENSE) and");
assertContains("vectors/README.md", "[NOTICE](../NOTICE).");
assertContains("fuzz/README.md", "See [LICENSE](../LICENSE) and");
assertContains("fuzz/README.md", "[NOTICE](../NOTICE).");
assertContains("vectors/manifest.json", "reallyme.jose.conformance.vector_manifest.v1");
assertContains("vectors/manifest.json", '"id": "panva-jose"');
assertContains("vectors/manifest.json", '"case_count": 4');
assertContains("vectors/panva-jose.json", '"suite": "panva-jose"');
assertContains("vectors/panva-jose.json", '"source": "panva/jose@6.2.3"');
assertContains("vectors/panva-jose.json", "panva-jose/jwe-ecdh-es-p256-a128gcm");
assertContains("vectors/panva-jose.json", "not a full algorithm matrix");
assertContains("vectors/panva-jose.json", "deterministic low scalars");
assertContains("vectors/README.md", "`tools/panva-goldens`");
assertContains("vectors/README.md", "`panva/jose@6.2.3`");
assertContains("vectors/README.md", "native Rust, Swift, Kotlin/JVM, and minified Android emulator lanes");
assertContains("vectors/README.md", "WASM lane executes all 94 applicable cases");
assertContains("vectors/README.md", "not a curve-by-content-encryption matrix");
assertContains("vectors/README.md", "panva/WebCrypto does not provide");
assertContains("vectors/README.md", "secp256k1 JOSE signing support");
assertContains("vectors/README.md", "does not add a JOSE-specific low-S normalization rule");
assertContains("vectors/README.md", "Face ID or Secure Enclave protected P-256 key");
assertContains("vectors/signed-jwt.json", "reallyme-jwt/kid-mismatch");
assertContains("README.md", "small native and WASM interop anchor");
assertContains("tools/panva-goldens/package.json", '"jose": "6.2.3"');
assertContains("tools/panva-goldens/package-lock.json", '"version": "6.2.3"');
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
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo install cargo-semver-checks --version \"$CARGO_SEMVER_CHECKS_VERSION\" --locked",
);
assertContains(".github/workflows/crates-package-preflight.yml", "cargo semver-checks --workspace");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "--exclude reallyme-jose-ffi",
);
assertContains(".github/workflows/crates-package-preflight.yml", "node scripts/run_pinned_release_readiness.mjs");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "run: node scripts/publish_crates_in_order.mjs order",
);
assertNotContains(".github/workflows/crates-release.yml", "environment:");
assertNotContains(".github/workflows/crates-release.yml", "if: inputs.publish");
assertNotContains(
  ".github/workflows/crates-release.yml",
  "Publish reallyme-jose crates after verified preflight and dry run",
);
assertContains(".github/workflows/crates-release.yml", "approved release SHA changed before publication");
assertContains(".github/workflows/crates-release.yml", "node scripts/verify_sdk_release_version.mjs");
assertContains(".github/workflows/crates-release.yml", "crates-package-preflight.yml");
assertContains(
  ".github/workflows/crates-release.yml",
  "run: node scripts/publish_crates_in_order.mjs order",
);
assertContains(".github/workflows/crates-release.yml", "RELEASE_ATTESTATION_PREFLIGHT_RUN_ID");
assertNotContains(".github/workflows/crates-release.yml", "git tag");
assertNotContains(".github/workflows/crates-release.yml", "gh release create");
assertNotContains(".github/workflows/crates-release.yml", "contents: write");
assertContains(".github/workflows/crates-release.yml", "Summarize crates.io publication");
assertContains(".github/workflows/crates-release.yml", "node-version: '24'");
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
assertContains(
  "scripts/publish_crates_in_order.mjs",
  "refusing to combine an unverified registry artifact with this release",
);
assertNotContains("scripts/publish_crates_in_order.mjs", "is already published; continuing");
assertContains("scripts/publish_crates_in_order.mjs", "checkPathDependencyVersions");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  'const REQUIRED_PUBLISH_ORDER_EDGES = [["reallyme-jose-proto", "reallyme-jose"]];',
);
assertContains("scripts/publish_crates_in_order.mjs", "checkRequiredPublishOrderEdges");
assertContains("scripts/publish_crates_in_order.mjs", "CRATES_IO_DEFAULT_RATE_LIMIT_RETRY_MS");
assertContains("scripts/publish_crates_in_order.mjs", "rate-limited");
assertNotContains("scripts/publish_crates_in_order.mjs", 'const PACKAGE = "reallyme-jose"');
assertContains("SECURITY.md", "security@really.me");
assertContains("SECURITY.md", "Report a vulnerability");
assertContains("SECURITY.md", "scripts/check_release_readiness.mjs");
assertContains("NOTICE", "ReallyMe JOSE");
assertNotContains("NOTICE", "ReallyMe Crypto");
assertNotContains("NOTICE", "BouncyCastle");
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: crates/proto/proto");
assertContains("buf.gen.yaml", "out: crates/proto/src/generated/buffa");
assertContains("buf.gen.yaml", "protoc-gen-buffa-packaging");
assertContains("buf.gen.yaml", "buf.build/apple/swift:v1.38.1");
assertContains("buf.gen.yaml", "out: gen/swift");
assertContains("buf.gen.yaml", "Visibility=Public");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/java:v35.1");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/kotlin:v35.1");
assertContains("buf.gen.yaml", "out: gen/java");
assertContains("buf.gen.yaml", "out: gen/kotlin");
assertContains("buf.gen.yaml", "buf.build/bufbuild/es:v2.12.1");
assertContains("buf.gen.yaml", "out: packages/ts/src/proto/generated");
assertContains(".gitignore", "!crates/proto/src/generated/");
assertContains(".gitignore", "!crates/proto/src/generated/**");
assertContains(".github/workflows/protobuf-ci.yml", `BUFFA_VERSION: ${buffaVersion}`);
assertNotContains(".github/workflows/protobuf-ci.yml", "buf breaking");
assertContains(".github/workflows/crates-package-preflight.yml", "buf generate");
assertContains(".github/workflows/protobuf-ci.yml", "scripts/release-readiness/core.mjs");
assertContains(".github/workflows/protobuf-ci.yml", "scripts/run_pinned_release_readiness.mjs");
for (const needle of releaseReadinessCheckoutRequired) {
  assertContains(".github/workflows/protobuf-ci.yml", needle);
  assertContains(".github/workflows/rust-ci.yml", needle);
  assertContains(".github/workflows/readiness.yml", needle);
}
assertContains(
  ".github/workflows/protobuf-ci.yml",
  `${releaseReadinessCommand} --generated-freshness --policy-only`,
);
assertContains(".github/workflows/rust-ci.yml", releaseReadinessCommand);
assertContains(".github/workflows/readiness.yml", releaseReadinessCommand);
assertContains(
  "scripts/run_pinned_release_readiness.mjs",
  `const RELEASE_READINESS_COMMIT = "${releaseReadinessCommit}"`,
);
assertContains(
  "scripts/run_pinned_release_readiness.mjs",
  '"fcc0b725a85784617568c29f1aa3382a206faaddc3a22012e46f0e35303e4e6d"',
);
assertContains("scripts/run_pinned_release_readiness.mjs", "LOCAL_CHECKER_SHA256");
assertContains("scripts/run_pinned_release_readiness.mjs", "MAX_CHECKER_BYTES = 524_288");
assertContains(
  "scripts/run_pinned_release_readiness.mjs",
  "local checker does not match the reviewed repository policy pin",
);
assertContains(
  "scripts/run_pinned_release_readiness.mjs",
  "vendored core does not match the reviewed upstream pin",
);
assertNotContains("scripts/run_pinned_release_readiness.mjs", "await fetch(");
assertNotContains("scripts/run_pinned_release_readiness.mjs", "raw.githubusercontent.com");
assertContains(
  ".github/workflows/release-readiness-drift.yml",
  "compare vendored release-readiness core",
);
assertContains(
  ".github/workflows/release-readiness-drift.yml",
  "ref: main",
);
assertContains(".github/workflows/crates-package-preflight.yml", "harden-generated-jose-proto.mjs");
assertContains(".github/workflows/protobuf-ci.yml", "node-version: '24'");
assertContains("scripts/harden-generated-jose-proto.mjs", "byteFieldNames");
assertContains("scripts/harden-generated-jose-proto.mjs", "Zeroize::zeroize");
assertContains("scripts/harden-generated-jose-proto.mjs", "deserialize_zeroizing_bytes");
assertContains("scripts/harden-generated-jose-proto.mjs", "__reallyme_zeroize_unknown_fields");
assertContains("scripts/harden-generated-jose-proto.mjs", "deny_unknown_fields");
assertContains("scripts/harden-generated-jose-proto.mjs", '"--check-idempotent"');
assertContains("scripts/harden-generated-jose-proto.mjs", '"JoseOperationRequest"');
assertContains("scripts/harden-generated-jose-proto.mjs", '"JoseOperationResponse"');
assertContains("scripts/harden-generated-jose-proto.mjs", "sensitiveOneofOwnerNames");
assertContains("scripts/harden-generated-jose-proto.mjs", "generatedModulePath");
assertContains("scripts/harden-generated-jose-proto.mjs", "expectedAllowAttributeCount = 4");
assertContains("crates/proto/Cargo.toml", 'zeroize = { workspace = true, optional = true }');
assertReallyMeProtobufReleasePolicy({
  buffaVersion,
  generatedFreshnessMode,
  workflowMode: "delegated",
  generatedFreshnessStepRun:
    `${releaseReadinessCommand} --generated-freshness --policy-only`,
  installBufRun: `set -euo pipefail
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
"$install_dir/buf" --version`,
  hardeningPolicy: {
    hardeningScript: "scripts/harden-generated-jose-proto.mjs",
    protoSchema: "crates/proto/proto/reallyme/jose/v1/jose.proto",
    generatedRust: "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
    generatedView: "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.__view.rs",
    protoCargo: "crates/proto/Cargo.toml",
    requiredScriptNeedles: [
      "byteFieldNames",
      "sensitiveOneofOwnerNames",
      "Zeroize::zeroize",
      "deserialize_zeroizing_bytes",
      "__reallyme_zeroize_unknown_fields",
      "deny_unknown_fields",
    ],
    requiredCargoNeedles: ['zeroize = { workspace = true, optional = true }'],
    // Every bytes/string field is deliberately classified. "Sensitive" here
    // means the generated owner must redact and wipe the value; compact JOSE
    // strings, key IDs, claims, keys, and public keys can all become persistent
    // account or identity correlators at SDK and telemetry boundaries.
    scalarFieldClassifications: [
      { message: "JoseJwsSignRequest", field: "private_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwsSignRequest", field: "payload", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseCompactResult", field: "compact", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwsVerifyRequest", field: "compact", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwsVerifyRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtEncodeUnsignedRequest", field: "claims_json", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtDecodeUnsignedRequest", field: "compact", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwtClaimsResult", field: "claims_json", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtSignRequest", field: "claims_json", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtSignRequest", field: "jwk_json", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtSignRequest", field: "private_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtSignRequest", field: "typ", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwtVerifyRequest", field: "compact", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwtVerifyRequest", field: "jwk_json", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtVerifyRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwtTemporalValidationPolicy", field: "expected_audience", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwtTemporalValidationPolicy", field: "expected_issuer", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwtTemporalValidationPolicy", field: "expected_subject", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJwtHeaderValidationPolicy", field: "accepted_typ_values", kind: "string", sensitivity: "public" },
      { message: "JoseJweEncryptRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJweEncryptRequest", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJweEncryptRequest", field: "kid", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJweEncryptRequest", field: "apu", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJweEncryptRequest", field: "apv", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJweEncryptRequest", field: "typ", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJweEncryptRequest", field: "cty", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJweDecryptRequest", field: "compact", kind: "string", sensitivity: "sensitive" },
      { message: "JoseJweDecryptRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseExpectedString", field: "value", kind: "string", sensitivity: "sensitive" },
      { message: "JoseExpectedBytes", field: "value", kind: "bytes", sensitivity: "sensitive" },
      { message: "JoseJwePlaintextResult", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
    ],
    requiredGeneratedNeedles: [
      "fn __reallyme_zeroize_unknown_fields(",
      "#[serde(default, deny_unknown_fields)]",
      "impl ::core::ops::Drop for JoseOperationResponse",
      "impl ::core::ops::Drop for JoseJweDecryptResponse",
      '.field("private_key", &"<redacted>")',
      '.field("plaintext", &"<redacted>")',
      '.field("expected_audience", &"<redacted>")',
      "::zeroize::Zeroize::zeroize(&mut self.private_key);",
      "::zeroize::Zeroize::zeroize(&mut self.expected_audience);",
    ],
    forbiddenGeneratedNeedles: [
      "::buffa::alloc::format!(",
      '.field("private_key", &self.private_key)',
      '.field("plaintext", &self.plaintext)',
    ],
    requiredViewNeedles: ['f.write_str("JoseJwsSignRequestOwnedView(<redacted>)")'],
  },
  generatedFreshness: {
    generatedPaths: ["crates/proto/src/generated", "gen/swift", "gen/java", "gen/kotlin"],
    commands: [
      ["buf", ["lint"]],
      ["buf", ["generate"]],
      ["node", ["scripts/harden-generated-jose-proto.mjs"]],
      ["node", ["scripts/harden-generated-jose-proto.mjs", "--check-idempotent"]],
      ["node", ["scripts/harden-generated-jose-jvm.mjs"]],
      ["node", ["scripts/harden-generated-jose-jvm.mjs", "--check-idempotent"]],
      ["cargo", ["fmt", "--package", "reallyme-jose-proto"]],
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
  "JOSE_ERROR_REASON_JWS_INVALID_COMPACT = 100;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWE_INVALID_COMPACT = 200;",
);
assertContains(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_COMPACT = 300;",
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
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "expiration validation fail open");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "Required to be nonzero");
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
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseJwsSignRequest");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseJwtSignRequest");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "message JoseJweEncryptRequest");
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  '.field("private_key", &"<redacted>")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  '.field("plaintext", &"<redacted>")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.__view.rs",
  'f.write_str("JoseJwsSignRequestOwnedView(<redacted>)")',
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.jose.v1.jose.rs",
  "::zeroize::Zeroize::zeroize(&mut self.private_key);",
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
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "Adapters must zeroize after dispatch");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "Presence-sensitive policy");
assertContains("crates/proto/proto/reallyme/jose/v1/jose.proto", "Sensitive decrypted plaintext bytes");
assertNotMatches(
  "crates/proto/proto/reallyme/jose/v1/jose.proto",
  /^\s*service\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/mu,
  "a protobuf service declaration",
);
assertNotContains("crates/jose/src/jwe/encrypt.rs", "new_with_ephemeral_private_key");
assertContains("crates/jose/src/wire/operation_response.rs", "pub fn execute_operation_v1<");
assertContains("crates/jose/src/wire/operation_response.rs", "pub fn execute_operation_json_v1<");
assertContains("crates/jose/src/wire/operation_response.rs", "pub fn decode_operation_response_v1(");
assertContains("crates/jose/src/wire/operation_response.rs", "JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V1");
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
assertContains("crates/jose/tests/jwe_tests.rs", "rejects_ecdh_es_epk_with_private_member");
assertContains("crates/jose/tests/jwe_tests.rs", "rejects_duplicate_epk_member");
assertContains("crates/jose/tests/jwe_tests.rs", "rejects_direct_jwe_with_ecdh_ephemeral_key_headers");
assertContains("crates/jose/tests/jwe_tests.rs", "rejects_invalid_ecdh_es_shared_secret_length_before_kdf");
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
assertContains(".github/workflows/rust-ci.yml", "cargo nextest run --locked --workspace --all-features");
assertContains(".github/workflows/rust-ci.yml", "Test publishable crates in the release profile");
assertContains(".github/workflows/rust-ci.yml", "cargo nextest run --release --locked -p reallyme-jose");
assertContains(".github/workflows/rust-ci.yml", "Format vector audit tool");
assertContains(".github/workflows/rust-ci.yml", "Independent vector audit");
assertContains(".github/workflows/rust-ci.yml", "--bin reallyme-jose-vector-audit -- .");
assertContains(".github/workflows/rust-ci.yml", "cargo audit --deny warnings");
assertContains(
  ".github/workflows/rust-ci.yml",
  `${releaseReadinessCommand} --policy-only`,
);
assertContains(".github/workflows/rust-ci.yml", "CARGO_CHECK_EXTERNAL_TYPES_VERSION: 0.5.0");
assertContains(".github/workflows/rust-ci.yml", "EXTERNAL_TYPES_NIGHTLY: nightly-2026-03-20");
assertContains(
  ".github/workflows/rust-ci.yml",
  'cargo +"${EXTERNAL_TYPES_NIGHTLY}" check-external-types',
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "--manifest-path crates/jose/Cargo.toml --all-features",
);
assertContains(".github/workflows/rust-ci.yml", "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER");
assertContains(".github/workflows/rust-ci.yml", "--test panva_vectors");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER",
);
assertContains(".github/workflows/crates-package-preflight.yml", "--test panva_vectors");
assertContains(".github/workflows/rust-ci.yml", "cargo-deny@${{ env.CARGO_DENY_VERSION }}");
assertContains(".github/workflows/rust-ci.yml", "cargo-audit@${{ env.CARGO_AUDIT_VERSION }}");
assertContains(".github/workflows/crates-package-preflight.yml", "cargo fmt --check");
assertContains(".github/workflows/crates-package-preflight.yml", "cargo check --locked --workspace");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "Test publishable crates in the release profile",
);
assertContains(".github/workflows/crates-package-preflight.yml", "cargo audit --deny warnings");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  'cargo +"${EXTERNAL_TYPES_NIGHTLY}" check-external-types',
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "--manifest-path crates/jose/Cargo.toml --all-features",
);
assertContains(".github/workflows/rust-ci.yml", "CARGO_NEXTEST_VERSION: 0.9.140");
assertContains(".github/workflows/crates-package-preflight.yml", "CARGO_NEXTEST_VERSION: 0.9.140");
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo-deny@${{ env.CARGO_DENY_VERSION }}",
);
assertContains(
  ".github/workflows/crates-package-preflight.yml",
  "cargo-audit@${{ env.CARGO_AUDIT_VERSION }}",
);
assertContains("deny.toml", "unknown-registry = \"deny\"");
assertContains("deny.toml", 'yanked = "deny"');
assertContains("deny.toml", 'multiple-versions = "deny"');
assertContains("deny.toml", 'name = "getrandom", version = "0.2.17"');
assertContains("deny.toml", 'name = "syn", version = "2.0.119"');

assertContains("crates/ffi/src/lib.rs", '#![allow(unsafe_code)]');
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
assertContains("crates/ffi/include/reallyme_jose.h", "All nonempty ranges must identify one live allocation");
assertContains("crates/ffi/include/reallyme_jose.h", "mutually disjoint");
assertContains("crates/ffi/README.md", "caller-owned buffer cleanup");
assertContains("crates/ffi/README.md", "must not infer");
assertContains("crates/ffi/README.md", "semantic errors from the C status alone");
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
assertContains("crates/ffi/tests/panic_guard.rs", "panic_payload_is_caught_and_mapped_without_escape");
assertContains(
  "crates/ffi/tests/panic_guard.rs",
  "extern_boundary_maps_deliberate_panic_to_stable_status",
);
assertContains("scripts/test_ffi_abi_release_artifact.sh", "header_smoke.c");
assertContains("scripts/test_ffi_abi_release_artifact.sh", "-u CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/test_ffi_abi_release_artifact.sh", "--profile release-ffi");
assertNotContains("scripts/test_ffi_abi_release_artifact.sh", "-C panic=unwind");
assertContains("scripts/test_ffi_abi_release_artifact.sh", '"${NM_TOOL}" -g');
assertContains("scripts/test_native_sanitizers.sh", "nightly-2026-07-01");
assertContains("scripts/test_native_sanitizers.sh", "-Zsanitizer=address");
assertContains("scripts/test_native_sanitizers.sh", "-Zub-checks=yes");
assertContains("scripts/test_native_sanitizers.sh", "-Zextra-const-ub-checks=yes");
assertContains(".github/workflows/rust-ci.yml", "scripts/test_ffi_abi_release_artifact.sh");
assertContains(".github/workflows/rust-ci.yml", "scripts/test_native_sanitizers.sh");

assertContains("Package.swift", "// swift-tools-version: 6.3");
assertContains("Package.swift", 'name: "reallyme-jose"');
assertContains("Package.swift", '.macOS(.v13)');
assertContains("Package.swift", '.iOS(.v16)');
assertContains("Package.swift", 'name: "ReallyMeJOSE"');
assertContains("Package.swift", 'exact: "1.38.1"');
assertContains("Package.swift", 'path: "gen/swift"');
assertContains("Package.swift", 'ffiArtifactVersion = "0.3.0"');
assertContains("Package.swift", 'ffiArtifactLocalPathOverride = ""');
assertNotContains("Package.swift", "0000000000000000000000000000000000000000000000000000000000000000");
assertContains("Package.swift", "REALLYME_JOSE_SWIFTPM_RUNTIME_FFI");
assertContains("Package.swift", ".reallyme-jose-runtime-ffi");
assertContains("Package.swift", "FileManager.default.fileExists");
assertContains("Package.swift", 'https://github.com/reallyme/jose/releases/download/v\\(ffiArtifactVersion)/ReallyMeJOSEFFI.xcframework.zip');
assertContains("Package.resolved", '"version" : "1.38.1"');
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
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "messageDepthLimit = 32");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "provider.clearOwned(&requestBytes)");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "provider.clearOwned(&responseBytes)");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "response.contractVersion == .v1");
assertContains("packages/swift/Sources/ReallyMeJOSE/ReallyMeJOSE.swift", "ReallyMeJOSEErrorReason(rawValue: protoReason.rawValue)");
assertContains("packages/swift/Sources/ReallyMeJOSE/MemoryHygiene.swift", "memset_s");
assertContains("packages/swift/Sources/ReallyMeJOSE/NativeProvider.swift", "try Self.requireCompatibleABI(version())");
assertContains("packages/swift/Sources/ReallyMeJOSE/NativeProvider.swift", "Resolve no operational symbol until");
assertContains("packages/swift/Sources/ReallyMeJOSE/NativeProvider.swift", "rm_jose_zeroize_buffer");
assertContains("packages/swift/Sources/ReallyMeJOSE/Errors.swift", "public enum ReallyMeJOSEErrorReason: Int");
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
]) {
  assertContains("packages/swift/Tests/ReallyMeJOSETests/ReallyMeJOSETests.swift", testName);
}
assertContains("packages/swift/README.md", "copy-on-write aliases");
assertContains("packages/swift/README.md", "Runtime loading is an explicit integration/testing mode");
assertContains("packages/swift/README.md", '.product(name: "ReallyMeJOSEProto", package: "jose")');
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
assertContains("scripts/prepare_swift_binary_manifest.mjs", "invalid-local-artifact-path");
assertContains("scripts/prepare_swift_release_candidate.sh", "scripts/build_swift_xcframework.sh");
assertContains(".github/workflows/swift-ci.yml", "runs-on: macos-26");
assertContains(".github/workflows/swift-ci.yml", "Select Xcode 26.6");
assertContains(".github/workflows/swift-ci.yml", "scripts/build_swift_xcframework.sh");
assertContains(".github/workflows/swift-ci.yml", ".reallyme-jose-runtime-ffi");
assertContains(".github/workflows/swift-package-preflight.yml", "Upload Swift release candidate");
assertContains(".github/workflows/swift-package-preflight.yml", "macos-26");
assertContains(".github/workflows/swift-package-preflight.yml", "Select Xcode 26.6");
assertContains(".github/workflows/swift-package-preflight.yml", "verify_swift_release_artifact.test.mjs");
assertContains(".github/workflows/swift-package-preflight.yml", "node scripts/run_pinned_release_readiness.mjs --release-packages");
assertContains(".github/workflows/rust-ci.yml", "--profile release-ffi");
const swiftPreflightSource = readText(".github/workflows/swift-package-preflight.yml");
if (
  swiftPreflightSource.indexOf("Upload Swift release candidate") >=
  swiftPreflightSource.indexOf("Bind manifest to Swift release candidate")
) {
  fail("Swift package preflight must upload immutable candidate bytes before rewriting Package.swift");
}
const swiftReleaseWorkflow = ".github/workflows/swift-package-release.yml";
assertContains(swiftReleaseWorkflow, "SwiftPM artifact verification");
assertContains(swiftReleaseWorkflow, "Download attested Swift artifact");
assertContains(swiftReleaseWorkflow, "Bind manifest to attested Swift artifact");
assertContains(swiftReleaseWorkflow, "Verify SwiftPM manifest and downloaded artifact");
assertContains(swiftReleaseWorkflow, "Download verified Swift artifact");
assertContains(swiftReleaseWorkflow, "Bind release manifest to verified Swift artifact");
assertContains(swiftReleaseWorkflow, "Create immutable GitHub release with Swift artifact");
assertContains(swiftReleaseWorkflow, "runs-on: macos-26");
assertContains(swiftReleaseWorkflow, "Select Xcode 26.6");
assertContains(swiftReleaseWorkflow, "RELEASE_ATTESTATION_PREFLIGHT_RUN_ID");
assertContains(swiftReleaseWorkflow, "environment: github-release");
assertContains(swiftReleaseWorkflow, 'GitHub release v${RELEASE_VERSION} already exists');
assertContains(
  swiftReleaseWorkflow,
  'Git tag v${RELEASE_VERSION} already targets a different commit',
);
assertContains(swiftReleaseWorkflow, "gh release create");
assertContains(swiftReleaseWorkflow, 'git tag "v${RELEASE_VERSION}" "${tag_target}"');
assertContains(swiftReleaseWorkflow, "--verify-tag");
assertContains(swiftReleaseWorkflow, "node scripts/run_pinned_release_readiness.mjs");
assertContains(swiftReleaseWorkflow, "node scripts/run_pinned_release_readiness.mjs --release-packages");
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
  "Download attested Swift artifact",
  "Bind manifest to attested Swift artifact",
  "Verify SwiftPM manifest and downloaded artifact",
  "Download verified Swift artifact",
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
assertContains(npmPreflightWorkflow, "npm package preflight");
assertContains(npmPreflightWorkflow, "run-name: npm package preflight ${{ inputs.version }}");
assertContains(npmPreflightWorkflow, "npm --prefix packages/ts test");
assertContains(npmPreflightWorkflow, "npm --prefix packages/ts run pack:check");
assertContains(npmPreflightWorkflow, "node scripts/run_pinned_release_readiness.mjs --release-packages");
assertContains(npmReleaseWorkflow, "Require current main and successful npm package checks");
assertContains(npmReleaseWorkflow, "build and verify immutable npm package");
assertContains(npmReleaseWorkflow, "Upload immutable npm tarball");
assertContains(npmReleaseWorkflow, "Download verified npm tarball");
assertContains(npmReleaseWorkflow, "Promote exact verified npm tarball");
assertContains(npmReleaseWorkflow, "RELEASE_ATTESTATION_PREFLIGHT_RUN_ID");
assertContains(npmReleaseWorkflow, "EXPECTED_TARBALL_SHA256");
assertContains(npmReleaseWorkflow, "sha256sum --check");
assertContains(npmReleaseWorkflow, 'npm publish "reallyme-jose-${RELEASE_VERSION}.tgz" --provenance --access public');
assertNotContains(npmReleaseWorkflow, "npm publish .");
const npmReleaseSource = readText(npmReleaseWorkflow);
let previousNpmReleaseBoundary = -1;
for (const boundary of [
  "Build immutable npm tarball",
  "Upload immutable npm tarball",
  "Download verified npm tarball",
  "Promote exact verified npm tarball",
]) {
  const boundaryIndex = npmReleaseSource.indexOf(boundary);
  if (boundaryIndex <= previousNpmReleaseBoundary) {
    fail(`npm release workflow boundary is missing or out of order: ${boundary}`);
  }
  previousNpmReleaseBoundary = boundaryIndex;
}
const npmPublishJob = npmReleaseSource.slice(npmReleaseSource.indexOf("  publish:"));
if (npmPublishJob.includes("wasm-pack@") || npmPublishJob.includes("npm --prefix packages/ts test")) {
  fail("npm publish job must promote the verified tarball without rebuilding it");
}
assertWorkflowPermissionsPolicy({
  path: npmReleaseWorkflow,
  workflow: { contents: "read" },
  jobs: {
    "verify-release-sha": { actions: "read", contents: "read" },
    publish: { actions: "read", contents: "read", "id-token": "write" },
  },
});
for (const workflow of [
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/swift-package-preflight.yml",
  ".github/workflows/kotlin-android-package-preflight.yml",
  npmPreflightWorkflow,
]) {
  assertContains(
    workflow,
    'release_sha:\n        description: Optional exact main commit SHA to certify. Leave blank to use current origin/main.\n        required: false\n        type: string\n        default: ""',
  );
  assertContains(workflow, 'if [ -n "${RELEASE_SHA_INPUT}" ]; then');
  assertContains(workflow, 'release_sha="$(git rev-parse origin/main)"');
  assertContains(workflow, "resolved release SHA is not the current origin/main tip");
  assertContains(workflow, "resolved release SHA does not match the workflow run head SHA");
}
for (const workflow of [
  ".github/workflows/crates-release.yml",
  ".github/workflows/swift-package-release.yml",
  ".github/workflows/kotlin-android-package-release.yml",
  npmReleaseWorkflow,
]) {
  assertNotContains(workflow, "inputs.release_sha");
  assertNotContains(workflow, "RELEASE_SHA_INPUT");
  assertNotContains(
    workflow,
    "description: Exact approved lowercase 40-character main commit SHA",
  );
  assertContains(workflow, 'release_sha="$(git rev-parse origin/main)"');
  assertContains(workflow, "resolved release SHA does not match the workflow run head SHA");
}
for (const workflow of [
  ".github/workflows/swift-package-release.yml",
  ".github/workflows/kotlin-android-package-release.yml",
  npmReleaseWorkflow,
]) {
  assertContains(workflow, "node scripts/verify_sdk_release_version.mjs");
}

assertContains("Cargo.toml", 'jni = "0.22.4"');
assertContains("crates/ffi/Cargo.toml", "jni = { workspace = true }");
assertContains("crates/ffi/src/lib.rs", "pub mod kotlin;");
assertContains("crates/ffi/src/kotlin.rs", "Java_me_really_jose_ReallyMeJoseNative_executeOperationNative");
assertContains("crates/ffi/src/kotlin.rs", "rm_jose_execute_operation_v1");
assertContains("crates/ffi/src/kotlin.rs", "Zeroizing<Vec<u8>>");
assertContains("packages/kotlin/build.gradle.kts", 'kotlin("jvm") version "2.4.0"');
assertContains("packages/kotlin/build.gradle.kts", "jvmToolchain(21)");
assertContains("packages/kotlin/build.gradle.kts", "lockAllConfigurations()");
assertContains("packages/kotlin/build.gradle.kts", 'api("com.google.protobuf:protobuf-javalite:4.35.1")');
assertContains("packages/kotlin/build.gradle.kts", "verifyJarContainsNativeResources");
assertContains("packages/kotlin/build.gradle.kts", "verifyJvmNativeManifest(");
assertContains("packages/kotlin/build.gradle.kts", "JVM native manifest source SHA does not match the checkout");
assertContains("packages/kotlin/build.gradle.kts", "verifyRemoteMavenPublishingConfigured");
assertNotContains("packages/kotlin/build.gradle.kts", "if (signingKeyValue != null)");
assertContains("packages/kotlin/gradle.properties", "org.gradle.dependency.verification=strict");
assertContains("packages/kotlin/gradle/wrapper/gradle-wrapper.properties", "distributionSha256Sum=");
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
assertContains("packages/kotlin/src/main/kotlin/me/really/jose/RustNativeProvider.kt", 'PosixFilePermissions.fromString("rwx------")');
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
assertContains("packages/kotlin/README.md", "owner-restricted directory");
assertContains("packages/kotlin/README.md", "JVM cannot promise native-style erasure");
assertContains("packages/kotlin/README.md", "Returned plaintext and claims arrays");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/jose/ReallyMeJose.kt",
  "responseBytes.fill(0)",
);
assertContains(".github/workflows/kotlin-ci.yml", "windows-2025");
assertContains(".github/workflows/kotlin-ci.yml", "verifyJarContainsNativeResources");
assertContains("packages/kotlin/build.gradle.kts", '"--profile", "release-ffi"');
assertContains("packages/kotlin/build.gradle.kts", 'environment.remove("CARGO_ENCODED_RUSTFLAGS")');
assertContains("packages/kotlin/build.gradle.kts", 'environment.remove("RUSTFLAGS")');
assertContains("packages/kotlin/build.gradle.kts", "../../target/release-ffi/");
assertNotContains("packages/kotlin/build.gradle.kts", "-C panic=unwind");
assertContains("scripts/build_kotlin_native_resource.sh", "windows-x86_64");
assertContains("scripts/build_kotlin_native_resource.sh", "--profile release-ffi");
assertContains("scripts/build_kotlin_native_resource.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/build_kotlin_native_resource.sh", "unset RUSTFLAGS");
assertContains("scripts/build_kotlin_native_resource.sh", "target/release-ffi/");
assertNotContains("scripts/build_kotlin_native_resource.sh", "-C panic=unwind");
assertContains("scripts/verify_native_artifact_handoff.mjs", "exact expected file set");
assertContains("scripts/verify_maven_release_repository.mjs", "Selected Maven publication artifacts");
assertContains("scripts/verify_maven_release_repository.mjs", "native manifest is not bound to the release source SHA");

assertContains("packages/kotlin-android/build.gradle.kts", 'id("com.android.library") version "9.3.0"');
assertContains("packages/kotlin-android/build.gradle.kts", "compileSdk = 36");
assertContains("packages/kotlin-android/build.gradle.kts", "minSdk = 24");
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
assertContains("scripts/build_android_native_resources.sh", "unset RUSTFLAGS");
assertContains("scripts/build_android_native_resources.sh", "release-ffi/libreallyme_jose_ffi.so");
assertNotContains("scripts/build_android_native_resources.sh", "-C panic=unwind");
assertContains("scripts/build_android_native_resources.sh", "llvm-strip");
assertContains("scripts/write_native_manifest.mjs", 'package: "reallyme-jose-native"');
assertContains("scripts/write_native_manifest.mjs", "GITHUB_SHA does not match the checked-out source SHA");
assertContains("scripts/test_android_consumer_r8_runtime.sh", "Android consumer R8 runtime gate passed");
assertContains("scripts/test_android_consumer_r8_runtime.sh", "app_installed");
assertContains("packages/kotlin-android/README.md", "API 24 or newer");
assertContains("packages/kotlin-android/README.md", "minified consumer APK");
assertContains("packages/kotlin-android/README.md", "16 KiB");
assertContains("packages/kotlin-android/gradlew", "../kotlin/gradlew");
assertContains("packages/kotlin-android/gradlew.bat", "..\\kotlin\\gradlew.bat");
assertNotContains("packages/kotlin-android/gradlew", 'cd "${SCRIPT_DIR}"');
assertNotContains("packages/kotlin-android/gradlew.bat", 'pushd "%SCRIPT_DIR%"');
assertContains("vectors/README.md", "all 96 checked-in cases");
assertContains(".github/workflows/android-ci.yml", "ndk;29.0.14206865");
assertContains(".github/workflows/android-ci.yml", "test_android_consumer_r8_runtime.sh");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "linux-aarch64");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "verify_maven_release_repository.mjs");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "kotlin-digest-${{ matrix.platform }}");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "build/kotlin-native-digests");
assertNotContains(".github/workflows/kotlin-android-package-preflight.yml", "needs.jvm-native.outputs");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "test_android_consumer_r8_runtime.sh");
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
assertContains(".github/workflows/kotlin-android-package-release.yml", "RELEASE_ATTESTATION_PREFLIGHT_RUN_ID");
assertContains(".github/workflows/kotlin-android-package-release.yml", "Download attested Maven publication repository");
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
assertContains("scripts/verify_release_attestation.mjs", "preflight-run-id-changed");
assertContains("scripts/verify_sdk_release_version.mjs", "Rust, Swift, JVM, Android, and TypeScript package versions");
assertContains(".github/workflows/crates-package-preflight.yml", "scripts/verify_sdk_release_version.test.mjs");
assertContains(".github/workflows/crates-package-preflight.yml", "scripts/publish_crates_in_order.test.mjs");
assertContains(".github/workflows/swift-package-preflight.yml", "scripts/verify_sdk_release_version.test.mjs");
assertContains(".github/workflows/kotlin-android-package-preflight.yml", "scripts/verify_sdk_release_version.test.mjs");

for (const file of listFiles("crates/ffi/src").filter((path) => path.endsWith(".rs"))) {
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

const explicitlyTestOnlyRustFiles = new Set([
  "crates/jose/src/operation_contract/jws/verify_tests.rs",
]);
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
  ".github/workflows/rust-ci.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/readiness.yml",
  ".github/workflows/release-readiness-drift.yml",
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
for (const workflow of requiredWorkflows) {
  assertContains(workflow, "SPDX-License-Identifier: Apache-2.0");
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
assertContains(".github/workflows/fuzz.yml", "pull_request:");
assertContains(".github/workflows/fuzz.yml", "schedule:");
assertContains(".github/workflows/fuzz.yml", "github.event_name == 'schedule'");
assertContains(".github/workflows/fuzz.yml", "nightly-2026-07-01");
assertNotContains(".github/workflows/fuzz.yml", "toolchain: nightly\n");
assertContains(".github/workflows/fuzz.yml", "CARGO_FUZZ_VERSION: 0.13.2");
assertContains(".github/workflows/fuzz.yml", "FUZZ_MAX_TOTAL_TIME_SECONDS: 900");
assertContains(
  ".github/workflows/fuzz.yml",
  "cargo metadata --manifest-path fuzz/Cargo.toml --locked --no-deps",
);
assertContains(".github/workflows/fuzz.yml", "git diff --exit-code -- fuzz/Cargo.lock");
assertContains(".github/workflows/fuzz.yml", "Restore and persist fuzz corpus");
assertContains(".github/workflows/fuzz.yml", "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9");
assertContains(
  ".github/workflows/fuzz.yml",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
);
assertNotContains(
  ".github/workflows/fuzz.yml",
  "actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4",
);
assertContains("fuzz/README.md", "`compact_jwe_ecdh_es`");
assertContains("fuzz/README.md", "`parse_jwe_header`");
assertContains("fuzz/README.md", "`validate_jwt_temporal`");
assertContains("fuzz/README.md", "`operation_wire`");
assertContains("fuzz/README.md", "`operation_response`");
assertContains("fuzz/README.md", "`ffi_operation`");
assertContains("fuzz/README.md", "every operation-contract semantic adapter");
assertContains("fuzz/README.md", "fuzz/dictionaries/jose.dict");
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
assertContains("tools/vector-audit/src/main.rs", "decrypt_jwe_with_cek(case, compact, &derived_cek)");
assertContains("tools/vector-audit/src/main.rs", "assert_expected_plaintext(case, &plaintext)");
assertContains("tools/panva-goldens/generate.mjs", "function cekLengthBits(enc)");
assertContains("tools/panva-goldens/generate.mjs", "const keyDataLenBits = cekLengthBits");
assertContains(".gitignore", "!packages/ts/src/proto/generated/");
assertContains(".gitignore", "!packages/ts/src/proto/generated/**");
assertNotContains(".gitignore", "packages/ts/wasm/");
assertContains(".gitignore", "/AGENTS.md");
assertContains(".github/workflows/readiness.yml", releaseReadinessCommand);
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
assertNotContains(".github/workflows/crates-release.yml", "release_ref:");
assertNotContains(".github/workflows/crates-release.yml", "inputs:");
assertContains(
  ".github/workflows/crates-release.yml",
  "release_sha: ${{ steps.resolve-release-sha.outputs.release_sha }}",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "release_version: ${{ steps.resolve-release-sha.outputs.release_version }}",
);
assertContains(
  ".github/workflows/crates-release.yml",
  'release_version="$(sed -n',
);
assertContains(
  ".github/workflows/crates-release.yml",
  "ref: ${{ needs.verify-release-sha.outputs.release_sha }}",
);
assertContains("scripts/publish_crates_in_order.mjs", "const fetchArgs =");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  '"--all-features",\n    "--locked",\n    "--offline"',
);
for (const workflow of [
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/crates-release.yml",
  ".github/workflows/rust-ci.yml",
]) {
  assertContains(workflow, "CARGO_HOME: ${{ runner.temp }}/package-preflight-cargo-home");
}

const pinnedBufDigest =
  "BUF_LINUX_X86_64_SHA256: d3de2838c68a5759ca276884254bc70df4e4ad185d6ed5f65f327b6ce6363eab";
for (const workflow of [
  ".github/workflows/crates-package-preflight.yml",
  ".github/workflows/protobuf-ci.yml",
]) {
  assertContains(workflow, "BUF_VERSION: 1.71.0");
  assertContains(workflow, pinnedBufDigest);
  assertContains(workflow, "--proto '=https' --tlsv1.2");
  assertContains(workflow, "sha256sum --check --strict");
  assertNotContains(workflow, "bufbuild/buf-setup-action@");
}

const setupNodeAction =
  "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0";
const expectedNodeSetupCounts = new Map([
  [".github/workflows/crates-package-preflight.yml", 1],
  [".github/workflows/crates-release.yml", 3],
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
  const node24Count = source.split("node-version: '24'").length - 1;
  const configuredNodeVersionCount = source.split("node-version:").length - 1;
  if (nodeCommandPattern.test(source) && setupCount === 0) {
    fail(`${workflow} invokes Node tooling without pinned actions/setup-node`);
  }
  if (source.includes("actions/setup-node@") && setupCount === 0) {
    fail(`${workflow} uses an unapproved actions/setup-node revision`);
  }
  if (node24Count !== setupCount || configuredNodeVersionCount !== setupCount) {
    fail(`${workflow} must configure Node 24 for every setup-node step`);
  }
  const expectedCount = expectedNodeSetupCounts.get(workflow);
  if (expectedCount !== undefined && setupCount !== expectedCount) {
    fail(`${workflow} must contain ${expectedCount} pinned Node 24 setup step(s)`);
  }
}
if (!rootCargo.includes("[workspace.lints.clippy]")) {
  fail("workspace clippy lint policy is missing");
}

if (!policyOnlyMode) {
  run(process.execPath, ["--test", "scripts/tests/operation-contract-readiness.test.mjs"]);
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
