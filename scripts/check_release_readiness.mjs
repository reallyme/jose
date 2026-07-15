#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const crateVersion = "0.2.0";
const protoCrateVersion = "0.2.0";
const cryptoVersion = "0.1.6";
const codecVersion = "0.1.20";

const trackedFilesResult = spawnSync("git", ["ls-files", "-z"], {
  cwd: root,
  encoding: "utf8",
});
if (trackedFilesResult.error) {
  throw trackedFilesResult.error;
}
if (trackedFilesResult.status !== 0) {
  process.stderr.write(trackedFilesResult.stderr);
  process.exit(trackedFilesResult.status ?? 1);
}
const trackedFiles = new Set(trackedFilesResult.stdout.split("\0").filter(Boolean));

function requireTracked(path) {
  if (!trackedFiles.has(path)) {
    fail(`${path} is not tracked by Git`);
  }
}

function readText(path) {
  requireTracked(path);
  return readFileSync(resolve(root, path), "utf8");
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function listFiles(path) {
  const prefix = `${path}/`;
  return [...trackedFiles].filter((file) => file.startsWith(prefix));
}

function fail(message) {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
}

function assertContains(path, needle) {
  if (!readText(path).includes(needle)) {
    fail(`${path} does not contain ${needle}`);
  }
}

function assertNotContains(path, needle) {
  if (readText(path).includes(needle)) {
    fail(`${path} must not contain ${needle}`);
  }
}

function assertNotMatches(path, pattern, description) {
  if (pattern.test(readText(path))) {
    fail(`${path} must not contain ${description}`);
  }
}

function assertLockPackageVersion(lock, name, version, source = null) {
  const blocks = lock.match(/\[\[package\]\]\n[\s\S]*?(?=\n\[\[package\]\]|\n*$)/g) ?? [];
  const block = blocks.find(
    (candidate) =>
      candidate.includes(`name = "${name}"\n`) && candidate.includes(`version = "${version}"\n`),
  );
  if (block === undefined) {
    fail(`Cargo.lock does not pin ${name} ${version}`);
  }
  if (source !== null && !block.includes(`source = "${source}"\n`)) {
    fail(`Cargo.lock ${name} ${version} does not use ${source}`);
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
    env: options.env ?? process.env,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    if (options.capture) {
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
    }
    process.exit(result.status ?? 1);
  }
  return result;
}

const rootCargo = readText("Cargo.toml");
assertContains("Cargo.toml", 'members = ["crates", "crates/proto/jose"]');
assertContains("Cargo.toml", 'exclude = ["fuzz"]');
assertContains("Cargo.toml", "overflow-checks = true");
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
  `reallyme-codec = { version = "${codecVersion}", default-features = false }`,
);
assertContains(
  "Cargo.toml",
  `reallyme-jose-proto = { version = "${protoCrateVersion}", path = "crates/proto/jose", default-features = false }`,
);
assertContains(
  "Cargo.toml",
  `reallyme-crypto = { version = "${cryptoVersion}", default-features = false }`,
);
assertNotContains("Cargo.toml", "reallyme-codec = { path");
assertNotContains("Cargo.toml", "reallyme-crypto = { path");
assertNotContains("Cargo.toml", 'time = "');

const crateCargo = readText("crates/Cargo.toml");
assertContains("crates/Cargo.toml", 'name = "reallyme-jose"');
assertContains("crates/Cargo.toml", `version = "${crateVersion}"`);
assertContains(
  "crates/Cargo.toml",
  'description = "JOSE, JWT, JWS, and JWE helpers for ReallyMe identity."',
);
assertContains("crates/Cargo.toml", "publish = true");
assertContains("crates/Cargo.toml", 'documentation = "https://docs.rs/reallyme-jose"');
assertContains("crates/Cargo.toml", 'categories = ["authentication", "cryptography", "encoding"]');
assertContains("crates/Cargo.toml", 'keywords = ["jose", "jwt", "jws", "jwe", "reallyme"]');
assertContains(
  "crates/Cargo.toml",
  'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
);
assertContains(
  "crates/Cargo.toml",
  'reallyme-codec = { workspace = true, features = ["base64", "base64url"] }',
);
assertContains("crates/Cargo.toml", "reallyme-crypto = { workspace = true }");
assertContains(
  "crates/Cargo.toml",
  'reallyme-jose-proto = { workspace = true, features = ["generated"], optional = true }',
);
assertContains("crates/Cargo.toml", 'wire = ["dep:buffa", "dep:reallyme-jose-proto"]');
assertContains("crates/Cargo.toml", "buffa = { workspace = true, optional = true }");
assertNotContains("crates/Cargo.toml", "reallyme-codec = { path");
assertNotContains("crates/Cargo.toml", "reallyme-crypto = { path");
assertNotContains("crates/Cargo.toml", "time = { workspace = true }");

assertContains("crates/proto/jose/Cargo.toml", 'name = "reallyme-jose-proto"');
assertContains("crates/proto/jose/Cargo.toml", `version = "${protoCrateVersion}"`);
assertContains(
  "crates/proto/jose/Cargo.toml",
  'description = "ReallyMe JOSE protobuf boundary messages generated with Buffa."',
);
assertContains(
  "crates/proto/jose/Cargo.toml",
  'categories = ["authentication", "cryptography", "encoding"]',
);
assertContains("crates/proto/jose/Cargo.toml", 'keywords = ["jose", "jwt", "jws", "jwe", "reallyme"]');
assertContains("crates/proto/jose/Cargo.toml", "publish = true");
assertContains("crates/proto/jose/Cargo.toml", 'generated = ["dep:buffa", "dep:serde"]');
assertContains("crates/proto/jose/Cargo.toml", 'default = ["generated"]');
assertContains(
  "crates/proto/jose/Cargo.toml",
  'documentation = "https://docs.rs/reallyme-jose-proto"',
);
assertContains("crates/proto/jose/Cargo.toml", "[package.metadata.docs.rs]");
assertContains("crates/proto/jose/Cargo.toml", "all-features = true");
assertContains("crates/proto/jose/Cargo.toml", '"/tests/**/*.rs"');
assertContains("crates/proto/jose/Cargo.toml", '"/proto/**/*.proto"');
assertContains(
  "crates/proto/jose/README.md",
  'reallyme-jose-proto = { version = "0.2.0", features = ["generated"] }',
);
assertContains("crates/proto/jose/README.md", "JoseOperationRequest");
assertContains("crates/proto/jose/README.md", "JoseProtoResultEnvelope");
assertContains("crates/proto/jose/README.md", "must treat those bytes as sensitive");
assertContains("crates/proto/jose/README.md", "Copyright © 2026 by ReallyMe LLC.");
assertContains("crates/proto/jose/NOTICE", "ReallyMe JOSE Proto");
assertContains(
  "crates/proto/jose/src/generated.rs",
  'pub const JOSE_PROTO_PACKAGE: &str = "reallyme.jose.v1";',
);

assertContains("crates/src/lib.rs", "pub use reallyme_crypto::{core::Algorithm, csprng::SecureRandom, jwk::Jwk, signer::Signer};");
assertContains("crates/src/lib.rs", "pub use serde_json::Value as JsonValue;");
assertContains("crates/src/lib.rs", "pub use zeroize::Zeroizing;");
assertContains("crates/src/lib.rs", "pub mod wire;");
assertContains("crates/src/lib.rs", '#[cfg(all(any(feature = "native", feature = "wasm"), feature = "wire"))]');
for (const file of [
  "crates/src/jwe/error.rs",
  "crates/src/jwe/validate_header.rs",
  "crates/src/jwt/error.rs",
  "crates/src/jws/suites/es256.rs",
  "crates/src/jws/suites/eddsa.rs",
  "crates/src/wire.rs",
]) {
  assertContains(file, "#[non_exhaustive]");
}
assertContains("crates/src/jwt/mod.rs", "decode_unsigned_jwt_claims_json");
assertContains("crates/src/jwt/mod.rs", "mod strict_json;");
assertContains("crates/src/jwt/strict_json.rs", "reject_duplicate_object_members");
assertContains(
  "crates/src/jwt/mod.rs",
  "decode_verify_jwt_claims_json_signature_only_with_header_validation",
);
assertContains("crates/src/jwt/verify.rs", "const ED25519_SIGNATURE_LEN: usize = 64;");
assertContains("crates/src/jwe/derive_key.rs", "JweError::InvalidSharedSecret");
assertContains("crates/src/jwe/derive_key.rs", "JweError::KeyDerivation");
assertContains("crates/src/jwe/validate_header.rs", "struct PublicEpkJwk");
assertContains(
  "crates/src/jwe/validate_header.rs",
  "validate_jwe_header_structure(",
);
assertContains("crates/src/wire.rs", "fn encode_claims_result(mut claims_json: Zeroizing<Vec<u8>>)");
assertNotContains("crates/src/wire.rs", "serde_json::to_vec(&claims)");
assertNotContains("crates/src/lib.rs", "mod codec;");
assertNotContains("crates/src/jws/sign.rs", "JwsSigningInputError::Codec");
assertNotContains("crates/src/jws/sign.rs", "encode_base64url");
assertNotContains("crates/src/jws/suites/es256.rs", "EncodingFailed");
assertNotContains("crates/src/jws/suites/eddsa.rs", "EncodingFailed");
assertNotContains("crates/src/jwe/error.rs", "EncodingFailed");
assertNotContains("crates/src/jwe/encrypt.rs", "encode_base64url");
assertNotContains("crates/src/jwe/validate_header.rs", "encode_base64url");
assertNotContains("crates/src/jwt/sign.rs", "encode_base64url");
assertNotContains("crates/src/jwt/unsigned.rs", "encode_base64url");
assertNotContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JWS_ENCODING_FAILED");
assertNotContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JWE_ENCODING_FAILED");
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8 = 4;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED = 72;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_KEY_DERIVATION_FAILED = 73;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "ES256K is supported by JWT through JWK algorithm binding",
);
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "reserved 3;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", 'reserved "JOSE_SIGNATURE_ALGORITHM_ES256K";');
assertNotContains("crates/src/wire.rs", "JOSE_SIGNATURE_ALGORITHM_ES256K");
assertNotContains("crates/src/lib.rs", "#![allow(missing_docs)]");

const lock = readText("Cargo.lock");
const cratesIo = "registry+https://github.com/rust-lang/crates.io-index";
assertLockPackageVersion(lock, "reallyme-codec", codecVersion, cratesIo);
assertLockPackageVersion(lock, "reallyme-crypto", cryptoVersion, cratesIo);
assertLockPackageVersion(lock, "reallyme-jose-proto", protoCrateVersion);

assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertContains("README.md", "crates.io/crates/reallyme-jose");
assertContains("README.md", `reallyme-jose = "${crateVersion}"`);
assertContains("README.md", "RSA JWS and RSA JWE algorithms");
assertContains("README.md", "JWT signing and verification for `ES256`, `ES256K`, and `EdDSA`");
assertContains("README.md", "## Crates");
assertContains("README.md", "publishes two Rust crates");
assertContains("README.md", "## Wire Boundary");
assertContains("README.md", "reallyme-jose-proto");
assertContains("README.md", "wire` feature is opt-in");
assertContains("README.md", "Owned wire output buffers use `Zeroizing<Vec<u8>>`");
assertContains("README.md", "Decode the returned `JoseProtoResultEnvelope`");
assertContains("README.md", "With the `wire` feature enabled");
assertContains("README.md", "returns the same binary `JoseProtoResultEnvelope` bytes");
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
assertContains("README.md", "wasm feature lane delegates P-256 ECDH point decompression");
assertContains("crates/README.md", "## Process-Proto Boundary");
assertContains("crates/README.md", "Owned wire outputs use zeroizing buffers");
assertContains("crates/README.md", "Treat that dependency as the adapter ABI");
assertContains("crates/README.md", "does not authenticate the sender");
assertContains("crates/README.md", "optional `wire` feature");
assertContains("crates/README.md", "native SDK users do not compile Buffa");
assertContains("crates/README.md", "With the `wire` feature enabled");
assertContains("crates/README.md", "process_json` changes request decoding only");
assertContains("crates/README.md", "verified claims JSON also reject duplicate object");
assertContains("crates/README.md", "accepts otherwise valid high-S signatures");
assertContains("crates/README.md", "Face ID and Secure Enclave protected");
assertContains("crates/README.md", "zeroize on drop");
assertContains("crates/README.md", "wasm lane depends on host-provider P-256");
assertContains("crates/README.md", "JWT wire header policy is presence-sensitive");
assertContains("crates/README.md", "JWT wire temporal validation is also explicit");
assertContains("crates/README.md", "JWE decrypt requests expose the native protected-header policy");
assertContains("crates/README.md", "large binary payloads are more efficient through the binary protobuf lane");
assertContains("crates/proto/jose/README.md", "It defines messages only");
assertContains("crates/proto/jose/README.md", "protobuf `service`, network transport");
assertContains("crates/proto/jose/README.md", "The intended adapter flow is");
assertContains("crates/proto/jose/README.md", "`process_json` entrypoint still returns the binary protobuf");
assertContains("crates/proto/jose/README.md", "JWE decrypt requests include a presence-sensitive");
assertContains("crates/proto/jose/README.md", "Pre-1.0");
for (const readme of ["README.md", "crates/README.md", "conformance/README.md", "fuzz/README.md"]) {
  assertContains(readme, "Copyright © 2026 by ReallyMe LLC.");
  assertContains(readme, "ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.");
}
assertContains("README.md", "See [LICENSE](LICENSE) and");
assertContains("README.md", "[NOTICE](NOTICE).");
assertContains("crates/README.md", "See [LICENSE](LICENSE) and");
assertContains("crates/README.md", "[NOTICE](NOTICE).");
assertContains("conformance/README.md", "See [LICENSE](../LICENSE) and");
assertContains("conformance/README.md", "[NOTICE](../NOTICE).");
assertContains("fuzz/README.md", "See [LICENSE](../LICENSE) and");
assertContains("fuzz/README.md", "[NOTICE](../NOTICE).");
assertContains("conformance/vectors/manifest.json", "reallyme.jose.conformance.vector_manifest.v1");
assertContains("conformance/vectors/manifest.json", '"id": "panva-jose"');
assertContains("conformance/vectors/manifest.json", '"case_count": 4');
assertContains("conformance/vectors/panva-jose.json", '"suite": "panva-jose"');
assertContains("conformance/vectors/panva-jose.json", '"source": "panva/jose@6.2.3"');
assertContains("conformance/vectors/panva-jose.json", "panva-jose/jwe-ecdh-es-p256-a128gcm");
assertContains("conformance/vectors/panva-jose.json", "not a full algorithm matrix");
assertContains("conformance/vectors/panva-jose.json", "deterministic low scalars");
assertContains("conformance/README.md", "`tools/panva-goldens`");
assertContains("conformance/README.md", "`panva/jose@6.2.3`");
assertContains("conformance/README.md", "native Rust test");
assertContains("conformance/README.md", "wasm crypto provider");
assertContains("conformance/README.md", "not a curve-by-content-encryption matrix");
assertContains("conformance/README.md", "panva/WebCrypto does not provide");
assertContains("conformance/README.md", "secp256k1 JOSE signing support");
assertContains("conformance/README.md", "does not add a JOSE-specific low-S normalization rule");
assertContains("conformance/README.md", "Face ID or Secure Enclave protected P-256 key");
assertContains("conformance/vectors/signed-jwt.json", "reallyme-jwt/kid-mismatch");
assertContains("README.md", "do not yet execute through");
assertContains("README.md", "the wasm provider");
assertContains("tools/panva-goldens/package.json", '"jose": "6.2.3"');
assertContains("tools/panva-goldens/package-lock.json", '"version": "6.2.3"');
assertContains("tools/panva-goldens/generate.mjs", "setKeyManagementParameters");
assertContains("tools/vector-audit/Cargo.toml", 'name = "reallyme-jose-vector-audit"');
assertContains("tools/vector-audit/src/main.rs", "PANVA_FILE");
assertContains("crates/tests/panva_vectors.rs", "panva_jose_vectors_interoperate");
assertContains(
  ".github/workflows/crates-release.yml",
  "Publish reallyme-jose",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "cargo nextest run --locked --workspace --all-features",
);
assertContains(".github/workflows/crates-release.yml", "cargo deny check");
assertContains(".github/workflows/crates-release.yml", "node scripts/check_release_readiness.mjs");
assertContains(".github/workflows/crates-release.yml", "reallyme-jose-v${version}");
assertContains(".github/workflows/crates-release.yml", "gh release create");
assertContains(".github/workflows/crates-release.yml", "--verify-tag");
assertContains(".github/workflows/crates-release.yml", "node-version: '24'");
assertContains("scripts/publish_crates_in_order.mjs", "cargo\", [\"metadata\"");
assertContains("scripts/publish_crates_in_order.mjs", "\"--locked\", \"--format-version\"");
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
assertContains("buf.yaml", "- path: crates/proto/jose/proto");
assertContains("buf.gen.yaml", "out: crates/proto/jose/src/generated/buffa");
assertContains("buf.gen.yaml", "protoc-gen-buffa-packaging");
assertContains(".gitignore", "!crates/proto/jose/src/generated/");
assertContains(".gitignore", "!crates/proto/jose/src/generated/**");
assertContains(".github/workflows/protobuf-ci.yml", "BUFFA_VERSION: 0.8.1");
assertContains(".github/workflows/protobuf-ci.yml", "buf lint");
assertNotContains(".github/workflows/protobuf-ci.yml", "buf breaking");
assertContains(".github/workflows/protobuf-ci.yml", "buf generate");
assertContains(".github/workflows/crates-release.yml", "buf generate");
assertContains(".github/workflows/crates-release.yml", "BUFFA_VERSION: 0.8.1");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "git diff --exit-code -- crates/proto/jose/proto crates/proto/jose/src",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "git status --porcelain -- crates/proto/jose/proto crates/proto/jose/src",
);
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "package reallyme.jose.v1;");
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  'option go_package = "github.com/reallyme/jose/gen/go/reallyme/jose/v1;josev1";',
);
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "option java_multiple_files = true;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", 'option java_outer_classname = "JoseProto";');
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", 'option java_package = "me.really.jose.v1";');
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", 'option swift_prefix = "ReallyMeProto";');
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "message JoseError");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JosePrimitiveError primitive = 1;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseProviderError provider = 2;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseBackendError backend = 3;");
assertNotContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JwsError jws = 1;");
assertNotContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JweError jwe = 2;");
assertNotContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JwtError jwt = 3;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "enum JoseErrorReason");
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWS_INVALID_COMPACT = 1;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWE_INVALID_COMPACT = 16;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_COMPACT = 37;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH = 49;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY = 50;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_JWK = 51;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME = 61;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY = 62;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF = 68;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_MALFORMED_JSON = 70;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_MISSING_OPERATION = 71;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED = 72;",
);
assertNotContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JOSE_ERROR_REASON_JWE_RANDOMNESS_FAILED");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "signature_only");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "uint64 now_unix = 6;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "expiration validation fail open");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "Required to be nonzero");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "message JoseProtoResultEnvelope");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "bytes payload = 2;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "message JoseOperationRequest");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseJwsSignRequest jws_sign = 1;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseJweDecryptRequest jwe_decrypt = 8;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "message JoseJwsSignRequest");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "message JoseJwtSignRequest");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "message JoseJweEncryptRequest");
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "JoseJweHeaderValidationPolicy header_policy = 5;",
);
assertContains(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  "message JoseJweHeaderValidationPolicy",
);
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "bool require_kid = 1;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseExpectedString expected_kid = 2;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseExpectedString expected_typ = 3;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseExpectedString expected_cty = 4;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseExpectedBytes expected_apu = 5;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "JoseExpectedBytes expected_apv = 6;");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "Adapters must zeroize after dispatch");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "Presence-sensitive policy");
assertContains("crates/proto/jose/proto/reallyme/jose/v1/jose.proto", "Result bytes may contain decrypted plaintext");
assertNotMatches(
  "crates/proto/jose/proto/reallyme/jose/v1/jose.proto",
  /^\s*service\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/mu,
  "a protobuf service declaration",
);
assertNotContains("crates/src/jwe/encrypt.rs", "new_with_ephemeral_private_key");
assertContains("crates/src/wire.rs", "pub fn process_proto");
assertContains("crates/src/wire.rs", "pub fn process_proto_output");
assertNotContains("crates/src/wire.rs", "pub fn process_proto_to_envelope_bytes");
assertContains("crates/src/wire.rs", "pub fn process_json");
assertContains("crates/src/wire.rs", "pub struct JoseProtoOutput");
assertContains("crates/src/wire.rs", "pub fn jose_proto_output_to_json");
assertContains("crates/src/wire.rs", "pub fn decode_proto_result_envelope");
assertContains("crates/src/wire.rs", "process_operation_result_bytes");
assertContains("crates/tests/wire_tests.rs", "jwe_invalid_key_length_is_not_authentication_failure");
assertContains(
  "crates/tests/wire_tests.rs",
  "jwe_wire_decrypt_enforces_presence_and_all_exact_header_values",
);
assertContains(
  "crates/tests/wire_tests.rs",
  "jwe_wire_decrypt_enforces_required_kid_presence",
);
assertContains(
  "crates/tests/wire_tests.rs",
  "jws_sign_rejects_non_utf8_payload_with_typed_reason",
);
assertContains("crates/tests/wire_tests.rs", "malformed_json_returns_backend_error_envelope");
assertContains("crates/tests/wire_tests.rs", "serialized_error_passes_through_rust_losslessly");
assertContains("crates/tests/wire_tests.rs", "jwt_verify_wire_rejects_jwk_public_key_mismatch");
assertContains("crates/tests/wire_tests.rs", "process_proto_dispatches_every_generated_operation");
assertContains("crates/tests/wire_tests.rs", "process_proto_missing_operation_returns_backend_error");
assertContains("crates/tests/wire_tests.rs", "process_proto_ignores_unknown_fields_on_valid_request");
assertContains(
  "crates/tests/wire_tests.rs",
  "process_proto_output_and_envelope_bytes_match_cose_style_adapter",
);
assertContains("crates/tests/wire_tests.rs", "jose_proto_output_json_round_trips_error_bytes");
assertContains("crates/tests/wire_tests.rs", "oversized_process_proto_input_returns_resource_limit");
assertContains("crates/tests/wire_tests.rs", "oversized_process_json_input_returns_resource_limit");
assertContains("crates/tests/wire_tests.rs", "oversized_jose_proto_output_json_returns_resource_limit");
assertContains("crates/tests/wire_tests.rs", "out_of_range_raw_signature_algorithm_is_provider_unsupported");
assertContains("crates/tests/wire_tests.rs", "jwt_verify_wire_requires_explicit_signature_only_mode");
assertContains("crates/tests/wire_tests.rs", "jwt_verify_wire_rejects_temporal_policy_without_now_unix");
assertContains("crates/tests/wire_tests.rs", "jwt_verify_wire_rejects_malformed_jwk_json");
assertContains("crates/tests/wire_tests.rs", "jwt_verify_wire_rejects_jwk_key_id_mismatch");
assertContains("crates/tests/wire_tests.rs", "every_jose_error_reason_passes_through_rust_envelope");
assertContains("crates/tests/jwt_suite/unsigned_reject_tests.rs", "reject_unsigned_with_duplicate_header_member");
assertContains("crates/tests/jwt_suite/unsigned_reject_tests.rs", "reject_unsigned_with_critical_header_parameter");
assertContains("crates/tests/jwt_suite/unsigned_reject_tests.rs", "reject_unsigned_with_duplicate_claim_member");
assertContains("crates/tests/jwt_suite/signed_reject_tests.rs", "reject_signed_jwt_with_duplicate_claim_members");
assertContains("crates/tests/jwt_suite/signed_reject_tests.rs", "reject_signed_eddsa_jwt_with_wrong_signature_length");
assertContains("crates/tests/jwe_tests.rs", "rejects_ecdh_es_epk_with_private_member");
assertContains("crates/tests/jwe_tests.rs", "rejects_duplicate_epk_member");
assertContains("crates/tests/jwe_tests.rs", "rejects_direct_jwe_with_ecdh_ephemeral_key_headers");
assertContains("crates/tests/jwe_tests.rs", "rejects_invalid_ecdh_es_shared_secret_length_before_kdf");
assertContains("crates/tests/jws_es256_tests.rs", "jws_es256_rejects_all_zero_signature_scalars");
assertContains("crates/tests/jws_es256_tests.rs", "jws_es256_rejects_r_scalar_at_group_order");
assertContains("crates/tests/jws_es256_tests.rs", "jws_es256_rejects_s_scalar_at_group_order");
assertContains("crates/tests/jws_es256_tests.rs", "jws_es256_accepts_high_s_signature_as_valid_ecdsa");
assertContains(
  "crates/proto/jose/tests/generated_tests.rs",
  "jose_operation_request_wire_contract_is_stable",
);
assertContains(
  "crates/proto/jose/tests/generated_tests.rs",
  "JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8.to_i32()",
);
assertNotContains("crates/src/lib.rs", "crates/envelopes");
assertContains("crates/src/lib.rs", "requires a supported runtime lane");
assertContains(".github/workflows/rust-ci.yml", "Check no-feature guidance");
assertContains(".github/workflows/rust-ci.yml", "cargo check --locked --workspace --all-features");
assertContains(".github/workflows/rust-ci.yml", "cargo nextest run --locked --workspace --all-features");
assertContains(".github/workflows/rust-ci.yml", "cargo install cargo-deny --version");
assertContains(".github/workflows/rust-ci.yml", "cargo install cargo-audit --version");
assertContains(".github/workflows/release-preflight.yml", "cargo metadata --locked");
assertContains(".github/workflows/release-preflight.yml", "cargo check --locked --workspace");
assertContains("deny.toml", "unknown-registry = \"deny\"");
assertContains("deny.toml", 'yanked = "deny"');
assertContains("deny.toml", 'multiple-versions = "deny"');
assertContains("deny.toml", 'name = "getrandom", version = "0.2.17"');

for (const file of listFiles("crates/src").filter((path) => path.endsWith(".rs"))) {
  const source = readText(file);
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
  "crates/src/jwe/compact.rs",
  "crates/src/jwe/header.rs",
  "crates/src/jwe/kdf.rs",
  "crates/src/jws/compact.rs",
  "crates/src/jws/header.rs",
  "crates/src/jwt/compact.rs",
  "crates/src/jwt/header.rs",
]) {
  if (listFiles("crates/src").includes(stale)) {
    fail(`${stale} should remain split into verb-named implementation files`);
  }
}

const requiredWorkflows = [
  ".github/workflows/rust-ci.yml",
  ".github/workflows/fuzz.yml",
  ".github/workflows/readiness.yml",
  ".github/workflows/release-preflight.yml",
  ".github/workflows/crates-release.yml",
  ".github/workflows/protobuf-ci.yml",
];
for (const workflow of requiredWorkflows) {
  assertContains(workflow, "SPDX-License-Identifier: Apache-2.0");
}

const fuzzCargo = readText("fuzz/Cargo.toml");
for (const target of [
  "compact_jwe",
  "compact_jwe_ecdh_es",
  "compact_jws_es256",
  "signed_jwt",
  "unsigned_jwt",
  "wire_process",
]) {
  assertContains("fuzz/Cargo.toml", `name = "${target}"`);
  assertContains(".github/workflows/fuzz.yml", `- ${target}`);
}
assertContains(".github/workflows/fuzz.yml", "pull_request:");
assertContains(".github/workflows/fuzz.yml", "schedule:");
assertContains(".github/workflows/fuzz.yml", "github.event_name == 'schedule'");
assertContains("fuzz/README.md", "`compact_jwe_ecdh_es`");
assertContains("fuzz/README.md", "`wire_process`");
assertContains("fuzz/README.md", "fuzz/dictionaries/jose.dict");
assertContains("fuzz/fuzz_targets/wire_process.rs", "process_proto");
assertContains("fuzz/fuzz_targets/wire_process.rs", "process_json");
assertContains("fuzz/fuzz_targets/compact_jwe_ecdh_es.rs", "P256EcdhEsJweKeyResolver");
assertContains("fuzz/dictionaries/jose.dict", "ECDH-ES");
for (const seed of [
  "fuzz/corpus/compact_jwe/direct-a128gcm",
  "fuzz/corpus/compact_jwe_ecdh_es/p256-a128gcm",
  "fuzz/corpus/compact_jws_es256/es256-valid",
  "fuzz/corpus/signed_jwt/es256-valid",
  "fuzz/corpus/unsigned_jwt/none-valid",
  "fuzz/corpus/wire_process/json-missing-operation",
]) {
  if (!listFiles("fuzz/corpus").includes(seed)) {
    fail(`${seed} is missing from the fuzz seed corpus`);
  }
}
assertContains("tools/vector-audit/src/main.rs", "decrypt_jwe_with_cek(case, compact, &derived_cek)");
assertContains("tools/vector-audit/src/main.rs", "assert_expected_plaintext(case, &plaintext)");
assertContains("tools/panva-goldens/generate.mjs", "function cekLengthBits(enc)");
assertContains("tools/panva-goldens/generate.mjs", "const keyDataLenBits = cekLengthBits");
assertNotContains(".gitignore", "!packages/ts/src/proto/generated/");
assertNotContains(".gitignore", "packages/ts/wasm/");
assertContains(".gitignore", "/AGENTS.md");
assertContains(".github/workflows/readiness.yml", "node scripts/check_release_readiness.mjs");
assertNotContains(".github/workflows/crates-release.yml", "release_ref:");
assertContains(
  ".github/workflows/crates-release.yml",
  "release_sha: ${{ steps.release-commit.outputs.sha }}",
);
assertContains(
  ".github/workflows/crates-release.yml",
  "ref: ${{ needs.dry-run.outputs.release_sha }}",
);
assertContains("scripts/publish_crates_in_order.mjs", "const fetchArgs =");
assertContains(
  "scripts/publish_crates_in_order.mjs",
  '"--all-features",\n    "--locked",\n    "--offline"',
);
for (const workflow of [
  ".github/workflows/crates-release.yml",
  ".github/workflows/release-preflight.yml",
  ".github/workflows/rust-ci.yml",
]) {
  assertContains(workflow, "CARGO_HOME: ${{ runner.temp }}/package-preflight-cargo-home");
}

const pinnedBufDigest =
  "BUF_LINUX_X86_64_SHA256: d3de2838c68a5759ca276884254bc70df4e4ad185d6ed5f65f327b6ce6363eab";
for (const workflow of [
  ".github/workflows/crates-release.yml",
  ".github/workflows/protobuf-ci.yml",
]) {
  assertContains(workflow, "BUF_VERSION: 1.71.0");
  assertContains(workflow, pinnedBufDigest);
  assertContains(workflow, "--proto '=https' --tlsv1.2");
  assertContains(workflow, "sha256sum --check --strict");
  assertNotContains(workflow, "bufbuild/buf-setup-action@");
}

const setupNodeAction =
  "actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444 # v5";
const expectedNodeSetupCounts = new Map([
  [".github/workflows/crates-release.yml", 2],
  [".github/workflows/readiness.yml", 1],
  [".github/workflows/release-preflight.yml", 1],
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

console.log("release readiness ok");
