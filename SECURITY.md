<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

`reallyme-jose` is security-sensitive JOSE infrastructure. Please report
suspected vulnerabilities privately rather than opening a public issue.

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through either channel:

- GitHub private vulnerability reporting: use the **"Report a vulnerability"**
  button under this repository's **Security** tab
  (`Security` -> `Advisories` -> `Report a vulnerability`).
- Email: **security@really.me**. For end-to-end encrypted disclosure, request
  our current PGP key in a first, contentless message; we will reply with it
  before you send details.

Please include, to the extent you can:

- affected crate version and feature lane;
- a minimal reproducer or malformed compact JOSE value when possible;
- whether the issue affects confidentiality, integrity, availability, or key
  binding policy;
- any known exposure window.

Do not include production secrets, private keys, access tokens, JWT claims with
PII, or raw user data in the report.

## Supported Surface

Security support currently covers the published `reallyme-jose` crate on
crates.io and its `native` feature lane.

The release readiness checks in `scripts/check_release_readiness.mjs`, the
dependency policy in `deny.toml`, and the fuzz harnesses under `fuzz/` are part
of the audit-facing maintenance contract for this crate.

## Signature Malleability

ES256 verification follows the JOSE ecosystem interoperability policy from
`reallyme-crypto`: high-S P-256 ECDSA signatures are accepted. This means an
ES256 JWS or JWT compact string is not a unique identifier for the signed
claims. Callers that deduplicate, revoke, cache, or audit by token hash must
canonicalize the signature representation first, or key those decisions on
validated claims and issuer-controlled identifiers instead of the raw compact
token bytes.

ES256K uses the stricter secp256k1 policy from `reallyme-crypto` and rejects
high-S signatures.

## JWE Authentication Semantics

Compact JWE decryption authenticates the protected header and ciphertext under
the content-encryption key. It does not authenticate the sender. With `dir`,
decryption proves only that the token was produced by someone with the direct
content-encryption key. With `ECDH-ES`, anyone with the recipient public key can
mint a syntactically valid encrypted message for that recipient.

Applications must not treat decrypted JWE claims as issuer-authenticated unless
the plaintext carries an independently verified signature, the key distribution
model provides sender authentication, or the application binds `apu`/`apv`,
`kid`, `typ`, and `cty` through an explicit policy before using the claims.

## WASM Trust Boundary

The `wasm` feature lane is build-checked so SDK packages can integrate it, but
its cryptographic assurance depends on JavaScript host functions supplied by the
selected `reallyme-crypto` provider. Point validation, ECDH, CSPRNG output, and
GCM tag verification are therefore only as trustworthy as that host provider.

Do not claim native-equivalent security for a WASM deployment until the selected
provider, bundler configuration, and browser or runtime crypto bindings have
been pinned, reviewed, and covered by release tests for that deployment.
