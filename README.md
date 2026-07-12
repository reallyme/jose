<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-jose

[![Rust CI](https://github.com/reallyme/jose/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/jose/actions/workflows/rust-ci.yml)
[![reallyme-jose](https://img.shields.io/crates/v/reallyme-jose?label=reallyme-jose&color=2563eb)](https://crates.io/crates/reallyme-jose)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

`reallyme-jose` is a focused JOSE layer for identity systems that need compact
JWS, JWT, and JWE handling without broad algorithm negotiation. It builds on
`reallyme-codec` and `reallyme-crypto` to provide strict protected-header
validation, explicit algorithm/key binding, typed non-PII errors, and portable
conformance vectors for SDK and protocol implementations.

## Supported JOSE Surface

`reallyme-jose` supports a deliberately small JOSE profile:

- compact JWS for `ES256` and `EdDSA`;
- signed and unsigned JWT parsing with algorithm/key binding, temporal policy, and `typ` policy;
- JWT signing and verification for `ES256`, `ES256K`, and `EdDSA`; `ES256K`
  is JWT-only and uses the low-S secp256k1 policy enforced by
  `reallyme-crypto`;
- compact JWE encryption and decryption for `dir` and `ECDH-ES`;
- AES-GCM content encryption with `A128GCM`, `A192GCM`, and `A256GCM`;
- ECDH-ES over P-256, P-384, and P-521 in the native lane;
- deterministic ECDH-ES ephemeral-key constructors only behind the
  `conformance-vectors` feature for vector reproduction.

The profile follows RFC 7515, RFC 7516, RFC 7518, RFC 7519, RFC 8725, and
RFC 9864. Algorithm identifiers map explicitly to ReallyMe crypto primitives;
caller-supplied JOSE headers never select arbitrary algorithms or keys. `EdDSA`
is accepted only with an Ed25519 JWK binding until the product adopts a fully
specified JOSE identifier from RFC 9864.

JWK parsing, serialization, validation, and thumbprints live in
`reallyme-crypto`. This crate consumes that JWK representation for algorithm,
curve, and `kid` binding, and rejects untrusted key-indirection headers in
compact JWS/JWT/JWE inputs.

The following JOSE features are not part of this profile and fail closed:

- RSA JWS and RSA JWE algorithms;
- AES Key Wrap and PBES2 key management;
- JWE JSON serialization;
- `b64`, `crit`, `zip`, `jku`, embedded `jwk`, `x5u`, and `x5c`
  protected-header parameters.

## Release Checks

The release path is Rust-first. CI runs formatting, linting, tests, native and
wasm feature-lane checks, dependency policy, advisory audit, release-readiness
checks, package inspection, and fuzz target builds. Documentation-only changes
do not trigger Rust CI.

Fuzz harnesses live in [fuzz](fuzz/) and cover compact JWS, JWT, and JWE parser
boundaries.

## Independent Vector Audit

Committed conformance vectors are checked by `tools/vector-audit`, a standalone
Rust binary that does not depend on `reallyme-jose`, `reallyme-crypto`, or
`reallyme-codec`. It validates the vector manifest, compact JOSE structure,
JWS/JWT signatures, unsigned JWT claims, and direct JWE AES-GCM fixtures with
independent crates.

## References

- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7516: JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html)
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 9864: Fully-Specified Algorithms for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9864.html)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
