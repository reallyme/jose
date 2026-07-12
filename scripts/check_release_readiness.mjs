#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const crateVersion = "0.1.0";
const cryptoVersion = "0.1.6";
const codecVersion = "0.1.1";

function readText(path) {
  return readFileSync(resolve(root, path), "utf8");
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function listFiles(path) {
  const absolute = resolve(root, path);
  return readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => {
    const child = `${path}/${entry.name}`;
    if (entry.isDirectory()) {
      return listFiles(child);
    }
    return [child];
  });
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
assertContains("Cargo.toml", 'members = ["crates"]');
assertContains("Cargo.toml", 'exclude = ["fuzz"]');
assertContains(
  "Cargo.toml",
  `reallyme-codec = { version = "${codecVersion}", default-features = false }`,
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
assertNotContains("crates/Cargo.toml", "reallyme-codec = { path");
assertNotContains("crates/Cargo.toml", "reallyme-crypto = { path");
assertNotContains("crates/Cargo.toml", "time = { workspace = true }");

assertContains("crates/src/lib.rs", "pub use reallyme_crypto::{core::Algorithm, csprng::SecureRandom, jwk::Jwk, signer::Signer};");
assertContains("crates/src/lib.rs", "pub use serde_json::Value as JsonValue;");
assertContains("crates/src/lib.rs", "pub use zeroize::Zeroizing;");
assertNotContains("crates/src/lib.rs", "#![allow(missing_docs)]");

const lock = readText("Cargo.lock");
assertContains("Cargo.lock", 'name = "reallyme-codec"');
assertContains("Cargo.lock", `version = "${codecVersion}"`);
assertContains("Cargo.lock", 'name = "reallyme-crypto"');
assertContains("Cargo.lock", `version = "${cryptoVersion}"`);
assertContains("Cargo.lock", 'source = "registry+https://github.com/rust-lang/crates.io-index"');

assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertContains("README.md", "crates.io/crates/reallyme-jose");
assertContains("README.md", "RSA JWS and RSA JWE algorithms");
assertContains("README.md", "JWT signing and verification for `ES256`, `ES256K`, and `EdDSA`");
assertContains("README.md", "Independent Vector Audit");
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
assertContains("tools/vector-audit/Cargo.toml", 'name = "reallyme-jose-vector-audit"');
assertContains(
  ".github/workflows/crates-release.yml",
  "Publish reallyme-jose",
);
assertContains("scripts/publish_crates_in_order.mjs", "cargo\", [\"metadata\"");
assertContains("scripts/publish_crates_in_order.mjs", "checkPathDependencyVersions");
assertNotContains("scripts/publish_crates_in_order.mjs", 'const PACKAGE = "reallyme-jose"');
assertContains("SECURITY.md", "security@really.me");
assertContains("SECURITY.md", "Report a vulnerability");
assertContains("SECURITY.md", "scripts/check_release_readiness.mjs");
assertContains("NOTICE", "ReallyMe JOSE");
assertNotContains("NOTICE", "ReallyMe Crypto");
assertNotContains("NOTICE", "BouncyCastle");
assertNotContains("crates/src/lib.rs", "crates/envelopes");
assertContains("crates/src/lib.rs", "requires a supported runtime lane");
assertContains(".github/workflows/rust-ci.yml", "Check no-feature guidance");
assertContains("deny.toml", "unknown-registry = \"deny\"");

for (const file of listFiles("crates/src").filter((path) => path.endsWith(".rs"))) {
  const source = readText(file);
  if (source.includes("pub use ") && source.includes("::*")) {
    fail(`${file} contains a wildcard re-export`);
  }
  if (source.includes("use ") && source.includes("::*")) {
    fail(`${file} contains a wildcard import`);
  }
  for (const forbidden of [
    "Result<",
    "unwrap(",
    "expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!(",
    "dbg!(",
    "println!(",
  ]) {
    if (["Result<"].includes(forbidden)) {
      continue;
    }
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
  ".github/workflows/release-preflight.yml",
  ".github/workflows/crates-release.yml",
];
for (const workflow of requiredWorkflows) {
  assertContains(workflow, "SPDX-License-Identifier: Apache-2.0");
}

const fuzzCargo = readText("fuzz/Cargo.toml");
for (const target of ["compact_jwe", "compact_jws_es256", "signed_jwt", "unsigned_jwt"]) {
  assertContains("fuzz/Cargo.toml", `name = "${target}"`);
}
if (!rootCargo.includes("[workspace.lints.clippy]")) {
  fail("workspace clippy lint policy is missing");
}

run("cargo", ["fmt", "--manifest-path", "tools/vector-audit/Cargo.toml", "--check"]);
run("cargo", [
  "clippy",
  "--manifest-path",
  "tools/vector-audit/Cargo.toml",
  "--all-targets",
  "--",
  "-D",
  "warnings",
]);
run("cargo", ["run", "--manifest-path", "tools/vector-audit/Cargo.toml", "--", "."]);

console.log("release readiness ok");
