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

This repository contains the Rust JOSE and protobuf crates, native C/JNI
adapter, Swift and Kotlin/JVM/Android packages, and TypeScript/WASM facade.
Report issues in any of these surfaces. Native and WASM algorithm support
differs; see the [supported JOSE surface](README.md#supported-jose-surface).

The release readiness checks in `scripts/check_release_readiness.mjs`, the
dependency policy in `deny.toml`, and the fuzz harnesses under `fuzz/` are part
of the automated validation used to maintain these packages.

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
the plaintext carries an independently verified signature or the key
distribution model separately establishes sender authentication. Binding
`apu`/`apv`, `kid`, `typ`, and `cty` through an explicit policy constrains the
protocol context; it does not establish who sent an ECDH-ES message because a
sender can choose those public header values.

## WASM Trust Boundary

The `wasm` feature lane executes the supported cryptographic operations in
package-owned Rust implementations compiled to WebAssembly. The JavaScript host
supplies secure randomness through Web Crypto; public-key validation, supported
ECDH agreement, and GCM tag verification remain inside `reallyme-crypto`.

The supported TypeScript facade requires explicit provider installation and
validates the canonical response contract. A substituted module can fabricate
results, so provider identity, bundler configuration, and the host randomness
source remain deployment trust boundaries. Pin and review them together with
the published package. Unsupported P-384 and P-521 ECDH-ES operations fail closed
in the WASM lane rather than falling back to an ambient provider.
