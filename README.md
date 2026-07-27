<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-jose

[![Rust CI](https://github.com/reallyme/jose/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/reallyme/jose/actions/workflows/rust-ci.yml)
[![reallyme-jose](https://img.shields.io/crates/v/reallyme-jose?label=reallyme-jose&color=2563eb)](https://crates.io/crates/reallyme-jose)
[![Maven Central](https://img.shields.io/maven-central/v/me.really/jose?label=maven)](https://central.sonatype.com/artifact/me.really/jose)
[![npm](https://img.shields.io/npm/v/@reallyme/jose?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/jose)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

`reallyme-jose` is a focused JOSE layer for identity systems that need compact
JWS, JWT, and JWE handling without broad algorithm negotiation. It builds on
`reallyme-codec` and `reallyme-crypto` to provide strict protected-header
validation, explicit algorithm/key binding, typed non-PII errors, and portable
conformance vectors for SDK and protocol implementations.

## Crates

This repository publishes two Rust crates:

- `reallyme-jose`: the ergonomic Rust SDK crate for compact JWS, JWT, and JWE;
- `reallyme-jose-proto`: checked-in Buffa protobuf bindings for the versioned
  JOSE wire boundary.

The workspace also builds the non-publishable `reallyme-jose-ffi` native
adapter for supported platform packages. Its versioned C ABI accepts the same
binary protobuf or generated ProtoJSON requests and returns only canonical V1
binary responses. The checked-in C header, Rust-exported limits, panic
firewall, pointer/alias validation, and cleanup function are part of that ABI.

The repository also contains the `ReallyMeJOSE` Swift 6.3 package for macOS 13
and iOS 16. Its typed JWS, JWT, and JWE facade uses the same canonical operation
contract through a checksum-bound XCFramework. The separately selectable
`ReallyMeJOSEProto` SwiftPM product exposes the generated operation messages for
applications that intentionally integrate at the wire boundary; the typed
facade remains the primary SDK product.

The `me.really:jose` Kotlin/JVM package exposes the equivalent typed facade to
Java 21 and Kotlin 2.4 callers. It reaches the same C ABI through JNI, loads
integrity-checked platform resources from an owner-restricted directory, and
keeps generated Java/Kotlin protobuf messages behind the supported API.

The separate `me.really:jose-android` AAR supports API 24 and newer with
`arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86` native libraries. Its build
binds every library to the source commit and verifies the completed archive;
CI also executes the minified release consumer on an Android emulator.

The `@reallyme/jose` TypeScript package exposes the same typed facade through
the canonical operation contract compiled to WebAssembly. Provider setup is
explicit, untrusted boundary values are validated before dispatch, and the
package zeroizes its owned copies of keys, plaintext, claims, and wire buffers.

Swift, Kotlin/JVM, the minified Android consumer, and TypeScript/WASM execute
the same 96 checked-in JWS, JWT, JWE, and panva conformance cases as Rust. Their
wire escape hatches additionally prove byte-identical binary
protobuf/ProtoJSON responses and exact typed negative mappings.

The TypeScript/WASM lane implements 94 of those cases. The P-384 and P-521
ECDH-ES cases are retained in its matrix and must return the typed
`providerUnsupported` result; there is no silent provider fallback.

Package publication is split into unprivileged preflight and credentialed
promotion workflows. Swift promotes the exact preflight XCFramework, while JVM
native artifacts are independently hashed by five producer jobs before Maven
assembly. Every release rechecks the current `main` SHA, the requested package
version, the latest successful preflight run, package metadata, native
inventories, and signed-publication configuration immediately before upload.

The Rust SDK remains the primary application-facing API. The protobuf crate is
published separately because Cargo requires optional normal dependencies to
exist in the registry, but the `wire` feature is opt-in so native SDK users do
not compile Buffa or generated protobuf code by default.

Release and CI validation use the immutable upstream-pinned readiness core and
audit the published dependency graph with:

```sh
node scripts/run_pinned_release_readiness.mjs
```

The normal readiness mode requires the declared crates.io versions and rejects
path or Git overrides. Maintainers may use the explicit local crypto or codec
audit switches only while intentionally auditing exact version-plus-path sibling
dependencies; those switches are not release modes and release CI does not set
them.

The protobuf boundary exists so FFI, WASM, Swift, Kotlin, TypeScript, and
out-of-process adapters can share one generated byte contract around the same
Rust dispatch and error semantics. It is not a second JOSE implementation and
does not define an RPC service, transport, endpoint, framing protocol, or
service-discovery model. Those concerns belong to the embedding application.

## Install

```toml
[dependencies]
reallyme-jose = "0.3.0"
```

```sh
npm install @reallyme/jose@0.3.0
```

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

The profile follows RFC 7515, RFC 7516, RFC 7518, RFC 7519, RFC 8725, and
RFC 9864. Algorithm identifiers map explicitly to ReallyMe crypto primitives;
caller-supplied JOSE headers never select arbitrary algorithms or keys. `EdDSA`
is accepted only with an Ed25519 JWK binding until the product adopts a fully
specified JOSE identifier from RFC 9864.

Unsigned JWT decoding is parsing only. It enforces the `alg = "none"` compact
shape but does not authenticate the sender, so verifier-grade paths must use
the signed JWT verification helpers.

JWK parsing, serialization, validation, and thumbprints live in
`reallyme-crypto`. This crate consumes that JWK representation for algorithm,
curve, and `kid` binding, and rejects untrusted key-indirection headers in
compact JWS/JWT/JWE inputs.

ES256 verification accepts both low-S and high-S ECDSA signatures that are
otherwise valid JOSE signatures. That is RFC 7515-compatible; applications that
deduplicate by token hash should canonicalize at a higher layer rather than
assuming every issuer emits one unique compact serialization. Face ID and Secure
Enclave protected P-256 keys may emit canonical signatures in practice, but this
verifier does not depend on that signer behavior: replay protection, audit
identity, and cache keys should be bound to the challenge, nonce, `jti`, payload
hash, and key identity rather than raw compact-token or signature bytes.
JWT-only ES256K verification is intentionally stricter: the secp256k1 backend
enforces low-S and rejects otherwise valid high-S signatures.

Signed JWT temporal validation accepts only positive, integral NumericDate
seconds. Fractional, negative, and zero values fail closed even though RFC
7519's NumericDate syntax is broader. Expiration remains exclusive after clock
skew is applied: a token is expired when `now - skew >= exp`.

Direct-key JWE encryption generates a fresh 96-bit IV for every message, but a
stateless encryptor cannot count all uses of a caller-owned CEK. Applications
must maintain an AES-GCM per-key invocation budget and rotate the CEK before the
applicable NIST SP 800-38D limit is reached.

ECDH-ES protected headers use a deliberately minimal `epk` profile. Only
`kty`, `crv`, `x`, and `y` are accepted. Additional standalone-JWK metadata
such as `kid`, `use`, or `alg`, private `d`, and zero-stripped coordinates fail
closed. The coordinates must use the full curve width required by RFC 7518.
The random source passed to compact-JWE encryption supplies the AES-GCM IV;
ephemeral ECDH keypairs are generated independently by the cryptographic
backend's CSPRNG.

Decoded claims can be returned as `serde_json::Value` or caller-owned types for
normal Rust SDK ergonomics. Those deserialized values are not zeroizing owners,
so privacy-sensitive callers should keep claim lifetimes short or use the
claims-JSON byte helpers when they need explicit zeroization at the JOSE
boundary.

The wasm feature lane uses package-owned Rust cryptographic implementations and
executes the applicable portable JOSE vectors under a JavaScript WASM host. The
host supplies secure randomness through the Web Crypto integration; public-key
validation and shared-secret calculation remain inside `reallyme-crypto`.

The following JOSE features are not part of this profile and fail closed:

- RSA JWS and RSA JWE algorithms;
- AES Key Wrap and PBES2 key management;
- JWE JSON serialization;
- `b64`, `crit`, `zip`, `jku`, embedded `jwk`, `x5u`, and `x5c`
  protected-header parameters.

## Wire Boundary

With the `wire` feature enabled, the `wire` module provides a transport-neutral,
Codec-style operation execution lane. Its byte-level flow is:

1. Encode one `JoseOperationRequest`, whose `oneof` selects the operation.
2. Pass those bytes to the versioned `execute_operation_v1` entrypoint.
3. Decode `JoseOperationResponse`, require contract version V1, require the
   response variant to match the submitted operation, and then handle its
   generated `result` or `error` outcome.

Malformed requests return a canonical response with a typed `boundary_error`.
After an operation is selected, success and failure remain nested under that
operation, so callers never infer result meaning from opaque bytes. The
`execute_operation_json_v1` entrypoint changes request decoding only and returns
the same binary `JoseOperationResponse` as `execute_operation_v1`.

The canonical versioned entrypoints are the only executable wire surface.
Pre-0.3 opaque response compatibility APIs have been removed; FFI, JNI, Swift,
Kotlin, and Android adapters all consume the same generated V1 response.

Wire errors preserve both the branch (`primitive`, `provider`, or `backend`) and
the exact `JoseErrorReason`. Malformed protobuf, malformed JSON, unsupported
algorithms, provider failures, invalid keys, invalid lengths, authentication
failures, and invalid signatures are kept distinct at this boundary.

JWT wire header policy is presence-sensitive: an omitted policy uses the
standard lenient `typ` behavior, while an explicitly default-constructed policy
is strict because `allow_missing_typ` defaults to false in protobuf.

JWT wire temporal validation is explicit: adapters must either set
`signature_only` or provide `temporal_policy` with a nonzero
`temporal_policy.now_unix`. This keeps an omitted proto3 timestamp from
silently disabling expiration checks.

JWE decrypt requests can carry a presence-sensitive protected-header policy.
Adapters can require `kid` and bind exact `kid`, `typ`, `cty`, `apu`, and `apv`
values. The wrapper messages distinguish an omitted expectation from an
explicitly expected empty string or byte sequence, which is required for
protocol context binding.

Owned wire output buffers use `Zeroizing<Vec<u8>>`. Responses can carry claims
JSON or decrypted plaintext, so adapters must treat returned bytes as sensitive
until they are handed to the next owner or destroyed.

The JSON adapter has a representation-specific text limit and, after decoding,
also rejects any message whose protobuf encoding would exceed the binary message
limit. This prevents JSON expansion from bypassing the binary resource budget;
the binary lane avoids JSON escaping and base64 expansion for large byte fields.

The canonical schema is shipped by `reallyme-jose-proto` under
`crates/proto/proto`; generated bindings are checked in under
`crates/proto/src/generated`. Refresh them with:

```sh
buf generate
cargo fmt --package reallyme-jose-proto
```

The opt-in wire lane intentionally exposes generated protobuf types
and Buffa enum wrappers as part of the public Rust boundary. That coupling is
the release contract for host-language and process-boundary adapters; normal SDK
callers should prefer the native `jws`, `jwt`, and `jwe` modules and avoid
enabling the wire feature unless they are implementing an operation adapter.

The protobuf and Rust crates are released together. While the project remains
pre-1.0, a new minor release may intentionally change the schema; consumers
should keep both crates and generated adapters on the same release line. The
repository enforces schema linting and generated-code freshness, but does not
promise wire compatibility with earlier pre-1.0 releases.

## Release Checks

The release path is Rust-first. CI runs formatting, linting, tests, native and
wasm feature-lane checks, dependency policy, advisory audit, release-readiness
checks, protobuf lint and generated-code freshness, package inspection, and fuzz
target builds. A separate release-readiness workflow runs for documentation-only
changes because README and policy text are part of the release contract.

Fuzz harnesses live in [fuzz](fuzz/) and cover compact JWS, JWT, and JWE parser
boundaries plus the protobuf/JSON process boundary.

## Independent Vector Audit

Committed conformance vectors are checked by `tools/vector-audit`, a standalone
Rust binary that does not depend on `reallyme-jose`, `reallyme-crypto`, or
`reallyme-codec`. It validates the vector manifest, compact JOSE structure,
JWS/JWT signatures, unsigned JWT claims, and direct JWE AES-GCM fixtures with
independent crates.

The `panva-jose` vectors add a small native and WASM interop anchor for ES256,
EdDSA, ES256 JWT, and ECDH-ES P-256/A128GCM. They are not intended to replace
the broader local negative and round-trip corpus.

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
