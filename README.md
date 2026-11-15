<div align="center">

# ReallyMe JOSE

**JSON Object Signing and Encryption for Identity**

[![Rust CI](https://github.com/reallyme/jose/actions/workflows/ci.yml/badge.svg)](https://github.com/reallyme/jose/actions/workflows/ci.yml)
[![reallyme-jose](https://img.shields.io/crates/v/reallyme-jose?label=reallyme-jose&color=2563eb)](https://crates.io/crates/reallyme-jose)
[![Maven Central](https://img.shields.io/maven-central/v/me.really/jose?label=maven)](https://central.sonatype.com/artifact/me.really/jose)
[![npm](https://img.shields.io/npm/v/@reallyme/jose?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/jose)
[![Security Policy](https://img.shields.io/badge/security-policy-0f766e)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)

</div>

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
binary protobuf or generated ProtoJSON requests and returns only canonical V2
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
package clears its owned byte arrays for keys, plaintext, claims, and wire
responses after use. The protobuf writer and JavaScript runtime can retain
additional copies, so this is best-effort erasure.

Swift, Kotlin/JVM, the minified Android consumer, and TypeScript/WASM execute
the same 104 checked-in JWS, JWT, JWE, and panva conformance cases as Rust. Their
wire APIs additionally test byte-identical binary
protobuf/ProtoJSON responses and exact typed negative mappings.

The TypeScript/WASM lane implements 98 of those cases. The P-384 and P-521
ECDH-ES cases are retained in its matrix and must return the typed
`providerUnsupported` result; there is no silent provider fallback.

Package publication is split into unprivileged preflight and credentialed
promotion workflows. Dispatch each package preflight with the version and full
`source_sha` while `main` points at the release commit. The preflights require
successful Required CI for that SHA. Publish the same version and SHA after all
preflights pass. The publish workflows promote the exact preflight artifacts
and verify their package-level digests or native inventory before upload.

The Android lane tests a minified consumer against the staged AAR. Maven
preflight reuses that publication and verifies the hashes of all five JVM
native producers before assembling both packages. Wait for a qualifying CI run
that retains the Android publication before dispatching Maven preflight.

Maintainers can build the equivalent signed Central Portal deployment bundle
locally. The script verifies one successful Kotlin/Android preflight for the
exact current commit and package version, downloads and verifies all producer
native digests, builds the Android libraries, tests both packages, and writes
the repository-layout archive beneath `build/maven-central-upload/out`:

Provide `MAVEN_SIGNING_PASSWORD` through a secret manager or a concealed shell
prompt before running these commands.

```sh
export MAVEN_SIGNING_KEY_ID='<long GPG key ID or fingerprint>'
export MAVEN_SIGNING_PASSWORD
export KOTLIN_NATIVE_RESOURCES_DIR="$PWD/build/kotlin-native-resources"
export ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/29.0.14206865"
scripts/maven-central-bundle.local.sh
```

The current commit must be available on `main` before the script can dispatch a
missing preflight. It never uploads the resulting bundle to Maven Central.

The Rust SDK provides borrowed application interfaces. The protobuf crate is
published separately because Cargo requires optional normal dependencies to
exist in the registry. Both supported runtime lanes include the generated
contract, which defines public operations, policies, algorithms, errors, and
limits. Native and generated APIs share semantic implementations.

Release and CI validation use the immutable upstream-pinned readiness core and
audit the published dependency graph with:

```sh
node .release-readiness/scripts/run-consumer-check.mjs
```

The `.release-readiness` checkout is pinned to commit
`7dffa0366a43fe9cc7b98a8040d37dd701d7955e` (release v0.9.0) before execution.
With that revision checked out alongside JOSE, check the public CI wiring and
generated bindings locally:

```sh
RELEASE_READINESS_PUBLIC_REPO=true node ../release-readiness/scripts/run-consumer-check.mjs --check-workflows
RELEASE_READINESS_PUBLIC_REPO=true RELEASE_VERSION=0.5.0 \
  node ../release-readiness/scripts/run-consumer-check.mjs \
  --generated-freshness --release-packages --policy-only
```

Release readiness requires the declared crates.io versions and rejects path or
Git overrides. Local sibling dependency substitutions must be removed before
running the release contract so the checked graph matches the dependencies that
consumers receive.

The protobuf boundary exists so FFI, WASM, Swift, Kotlin, TypeScript, and
out-of-process adapters can share one generated byte contract around the same
Rust dispatch and error semantics. It is not a second JOSE implementation and
does not define an RPC service, transport, endpoint, framing protocol, or
service-discovery model. Those concerns belong to the embedding application.

## Install

```toml
[dependencies]
reallyme-jose = "0.5.0"
```

```sh
npm install @reallyme/jose@0.5.0
```

## Supported JOSE Surface

`reallyme-jose` supports a deliberately small JOSE profile:

- compact JWS for `ES256` and `EdDSA`;
- unsigned JWT parsing, plus signed JWT verification with algorithm/key binding,
  temporal policy, and `typ` policy;
- JWT signing and verification for `ES256`, `ES256K`, and `EdDSA`; `ES256K`
  is JWT-only and uses the low-S secp256k1 policy enforced by
  `reallyme-crypto`;
- compact JWE encryption and decryption for `dir` and `ECDH-ES`;
- AES-GCM content encryption with `A128GCM`, `A192GCM`, and `A256GCM`;
- ECDH-ES over P-256, P-384, and P-521 in the native lane;
- opt-in compact-JWE compression with raw DEFLATE (`zip = "DEF"`).

The profile follows RFC 7515, RFC 7516, RFC 7518, RFC 7519, and RFC 8725.
It binds the `EdDSA` identifier to Ed25519, but does not yet accept RFC 9864's
fully specified `Ed25519` identifier. Algorithm identifiers map explicitly to
ReallyMe crypto primitives;
caller-supplied JOSE headers never select arbitrary algorithms or keys. `EdDSA`
identifies Ed25519 only; signed JWT verification checks the JWK algorithm and
curve binding.

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
skew is applied: a token is expired when `now - skew >= exp`. Verification
time must be positive, and clock/issued-at skew may not exceed 300 seconds.

Direct-key JWE encryption generates a fresh 96-bit IV for every message, but a
stateless encryptor cannot count all uses of a caller-owned CEK. Applications
must maintain an AES-GCM per-key invocation budget and rotate the CEK before the
applicable NIST SP 800-38D limit is reached.
The Swift and Kotlin FFI adapters use a sizing call followed by a write call;
each direct-key encryption request consumes two AES-GCM invocations under the
caller-owned CEK. Count both when enforcing that budget.

Compact-JWE compression is disabled by default. Encryption compresses with the
raw DEFLATE format before AES-GCM encryption and serializes `zip = "DEF"` in the
protected header. Decryption authenticates the complete compact JWE before it
inflates plaintext, rejects trailing compressed data, and enforces a 1 MiB
decompressed-plaintext ceiling. The live compressed and decompressed plaintext
owners are zeroized on drop. Codec workspaces and allocator copies created
during growth may retain data; strict erasure requirements should leave `DEF`
disabled. Callers must opt in to `DEF` through the protected-header
policy; an empty allowlist rejects every `zip` value.

Compression changes the ciphertext length and can expose secret-dependent size
information when attacker-controlled and confidential values share a
plaintext. Do not enable it for such mixed-origin content. Protocol adapters
must negotiate compression before calling the primitive. In OpenID4VCI 1.0,
issuers that enable this primitive advertise `zip_values_supported: ["DEF"]`;
absence of that metadata means the request must remain uncompressed.

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
- `b64`, `crit`, `jku`, and `x5u` protected-header parameters, plus every `zip`
  value other than the explicitly enabled `DEF` algorithm.

Embedded `jwk` headers are rejected by default. JWE also rejects embedded
`x5c`. An explicit signed-JWT header policy can tolerate `jwk` or `x5c`
presence, but ignores their contents: key selection and verification still use
the caller-supplied JWK and public key. Compact JWS accepts non-critical `x5c`
and JAdES metadata without interpreting it so callers can obtain the exact
signed header from an authenticated-parts verification API. Profile-aware
callers must bind that returned metadata to the supplied verification key.

## Wire Boundary

The `wire` module provides a transport-neutral,
Codec-style operation execution lane. Its byte-level flow is:

1. Encode one `JoseOperationRequest`, whose `oneof` selects the operation.
2. Pass those bytes to the versioned `execute_operation_v1` entrypoint.
3. Decode `JoseOperationResponse`, require contract version V2, require the
   response variant to match the submitted operation, and then handle its
   generated `result` or `error` outcome.

Malformed requests return a canonical response with a typed `boundary_error`.
After an operation is selected, success and failure remain nested under that
operation, so callers never infer result meaning from opaque bytes. The
`execute_operation_json_v1` entrypoint changes request decoding only and returns
the same binary `JoseOperationResponse` as `execute_operation_v1`.

The canonical versioned entrypoints are the only executable wire surface.
FFI, JNI, Swift, Kotlin, Android, and TypeScript/WASM adapters consume the same
generated V2 response. The `_v1` function suffix refers to native function ABI;
the response contract version is checked separately.

Wire errors preserve both the branch (`primitive`, `provider`, or `backend`) and
the exact `JoseErrorReason`. Malformed protobuf, malformed JSON, unsupported
algorithms, provider failures, invalid keys, invalid lengths, authentication
failures, and invalid signatures are kept distinct at this boundary.

The same JOSE operation failure carries the same protobuf branch and
`JoseErrorReason` through Swift, TypeScript/WASM, and Kotlin/JNI. Each SDK
surfaces it through its public error type. A distinction belongs in
`JoseErrorReason` when consumers of the shared operation response need it.

SDK setup and provider-response failures use `JoseSdkErrorCode` locally.
A distinct code gives callers a specific diagnosis or recovery action.
TypeScript preserves its string `code` and exposes the protobuf value as
`schemaCode`. Swift and JVM errors expose the protobuf value as `code`.

| SDK | Provider setup failures |
| --- | --- |
| TypeScript/WASM | Explicit installation is required. A missing provider reports `PROVIDER_NOT_INSTALLED`, and setup failures report `PROVIDER_FAILURE`. |
| Swift | The native loader distinguishes unsupported platform, missing library, load failure, missing symbol, and incompatible ABI. For `nativeSymbolMissing`, check the library's exports. |
| Kotlin/Java and Android | The native loader reports setup failures through `NativeProviderFailure` with `PROVIDER_FAILURE`. |

JWT wire header policy is presence-sensitive: an omitted policy requires an
explicit `typ: JWT` header. To accept tokens from a legacy issuer that omits
`typ`, set `allow_missing_typ` in an explicit policy.

JWT verification requires one `verification.mode`: `signature_only`, `claims`,
or `temporal_only`. Time-validating modes require a valid current time and
bounded skew. JWT signing uses optional `header_options`: absence defaults to
`typ: JWT`, a present message without `typ` omits it, and an empty `typ` is invalid.

JWE decrypt requests can carry a presence-sensitive protected-header policy.
Adapters can require `kid` and bind exact `kid`, `typ`, `cty`, `apu`, and `apv`
values. The wrapper messages distinguish an omitted expectation from an
explicitly expected empty string or byte sequence, which is required for
protocol context binding.

Owned wire output buffers use `Zeroizing<Vec<u8>>`. Responses can carry claims
JSON or decrypted plaintext, so adapters must treat returned bytes as sensitive
until they are handed to the next owner or destroyed.

Compact JOSE tokens are limited to 1 MiB. Binary operation requests, including
protobuf overhead, are also limited to 1 MiB, so usable payload space depends
on headers, keys, and encoding expansion.

The JSON adapter has a 1.5 MiB text limit and, after decoding,
also rejects any message whose protobuf encoding would exceed the binary message
limit. This prevents JSON expansion from bypassing the binary resource budget;
the binary lane avoids JSON escaping and base64 expansion for large byte fields.

The canonical schema is shipped by `reallyme-jose-proto` under
`crates/proto/proto`; generated bindings are checked in under
`crates/proto/src/generated`. Refresh them with:

```sh
node scripts/generate-jose-proto.mjs
```

`api::contract` exposes generated protobuf types and Buffa enum wrappers.
The Rust runtime and generators use the exact ReallyMe Buffa 0.1.1 family.
The generator configures cleanup, guarded JSON, and borrowed views in
`buf.gen.yaml`.
`api::execute` executes generated requests; `api::execute_with_providers` accepts
caller-scoped signing and JWE capabilities through nonzero handles. The contract
also represents raw P-256 signatures, standalone ECDH-ES derivation, temporal-only
JWT verification, claim parsing, suite metadata, and supported contract limits.

The protobuf and Rust crates are released together. While the project remains
pre-1.0, a new minor release may intentionally change the schema; consumers
should keep both crates and generated adapters on the same release line.
V2 intentionally removes legacy presence/policy fields and redundant per-area
error codes. Their numbers and names are reserved. All SDKs and native/WASM
binaries must be rebuilt together; old response versions fail closed. The
repository checks compatibility against the frozen V2 descriptor and checks
schema reachability and generated-code freshness. See the
[protobuf contract](crates/proto/README.md) for migration details.

## Release Checks

The release path is Rust-first. CI runs formatting, linting, tests, native and
wasm feature-lane checks, dependency policy, advisory audit, release-readiness
checks, protobuf lint and generated-code freshness, package inspection, and fuzz
target builds. The policy lane also runs for documentation-only changes.
GitHub aggregates the applicable lanes in the `Required CI` check and reports
the contributor agreement separately.

Fuzz harnesses live in [fuzz](fuzz/) and cover compact JWS, JWT, and JWE parser
boundaries plus the protobuf/JSON process boundary.

## Independent Vector Audit

Committed conformance vectors are checked by `tools/vector-audit`, a standalone
Rust binary that does not depend on `reallyme-jose`, `reallyme-crypto`, or
`reallyme-codec`. It validates the vector manifest, compact JOSE structure,
JWS/JWT signatures, unsigned JWT claims, and JWE AES-GCM fixtures with
independent crates. For ECDH-ES fixtures it checks decryption using the recorded
derived CEK; it does not independently recompute ECDH or Concat-KDF. The panva
fixtures provide a separate implementation anchor for that agreement path.

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

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

Third-party components retain their own licenses and notices.

## Copyright And Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
