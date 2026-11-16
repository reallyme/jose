# reallyme-jose

`reallyme-jose` provides compact JOSE, JWT, JWS, and JWE helpers for ReallyMe
identity workflows.

The crate keeps the JOSE policy layer separate from lower-level primitives:

- cryptographic operations go through `reallyme-crypto`;
- the exact `Algorithm` type used by JWT/JOSE helpers is re-exported from this
  crate, so consumers do not need a separate `reallyme-crypto-core` dependency;
- codec operations go through `reallyme-codec`.

The companion `reallyme-jose-proto` crate publishes the generated protobuf
types included by both runtime lanes. It is versioned with this crate so
FFI, WASM, Swift, Kotlin, TypeScript, and generated-SDK adapters can share one
transport-neutral operation contract. It does not define a network or RPC
protocol; the embedding adapter owns transport and lifecycle concerns. The
schema is the public contract for operations, policies, algorithms, and errors.
`api::contract` re-exports the generated types, while `api::execute` and
`api::execute_with_providers` execute them through the same semantic functions
as the borrowed native APIs. Injected provider handles are scoped to the caller.

## Install

```toml
[dependencies]
reallyme-jose = "0.5.1"
```

## Security Model

- JWT verification binds the token header algorithm to the supplied JWK
  algorithm and curve metadata, the JWK `kid` when present, and the caller's
  public-key bytes.
- Unsigned JWT decoding is parsing only; it does not authenticate the sender.
- The canonical protobuf wire boundary returns a versioned
  `JoseOperationResponse` whose generated oneofs preserve the selected
  operation, success/error outcome, error branch, and exact `JoseErrorReason`.
- Owned wire outputs use zeroizing buffers because result bytes can contain
  claims JSON, decrypted plaintext, or structured error bytes.
- Compact JWS, signed JWT, and compact JWE parsing reject duplicate protected
  header members before policy evaluation.
- Unsigned JWT parsing and verified claims JSON also reject duplicate object
  members so mixed deployments cannot disagree on first-wins versus last-wins
  claim interpretation.
- `b64`, `crit`, `jku`, and `x5u` protected-header parameters fail closed.
  Compact-JWE `zip = "DEF"` is supported only when the caller explicitly adds
  the typed DEFLATE algorithm to the protected-header policy; every other `zip`
  value is rejected as unsupported.
  Embedded `jwk` headers are rejected. JWE also rejects `x5c`. An explicit
  signed-JWT header policy can allow `jwk` or `x5c` presence, but ignores their
  contents; the supplied JWK and public key remain authoritative. Compact JWS
  accepts non-critical `x5c` and JAdES metadata without interpreting it so the
  authenticated-parts APIs can return the exact signed header. Profile-aware
  callers must bind that returned metadata to the supplied verification key.
- ES256 verification accepts otherwise valid high-S signatures as RFC 7515
  permits; applications should not use compact-token byte equality as an
  issuer-independent uniqueness guarantee. Face ID and Secure Enclave protected
  P-256 signers may produce canonical signatures, but verifier acceptance is
  based on JOSE/P-256 ECDSA validity rather than that platform-specific emission
  detail. JWT-only ES256K verification intentionally differs: the secp256k1
  backend enforces low-S and rejects otherwise valid high-S signatures.
- Signed JWT temporal validation accepts only positive, integral NumericDate
  seconds. Fractional, negative, and zero values are rejected as a deliberate
  fail-closed profile even though RFC 7519's NumericDate syntax is broader.
- Direct-key JWE encryption generates a fresh 96-bit IV but cannot count uses of
  a caller-owned CEK. Callers must enforce an AES-GCM per-key invocation budget
  and rotate the CEK before the applicable NIST SP 800-38D limit.
  Swift and Kotlin FFI adapters use two AES-GCM invocations for each direct-key
  request because they perform a sizing call and a write call.
- Raw DEFLATE compression, when requested, runs before encryption. Decryption
  authenticates AES-GCM before inflating, rejects trailing compressed data, and
  caps decompressed plaintext at 1 MiB. Intermediate compressed and
  decompressed plaintext owners zeroize on drop. Codec workspaces and allocator
  copies created during growth can retain data; strict erasure requirements
  should leave compression disabled. Compression remains disabled
  by default because ciphertext length can expose secret-dependent information;
  do not mix attacker-controlled and confidential values in compressed content.
  OpenID4VCI adapters may advertise `zip_values_supported: ["DEF"]` only when
  they opt in to this policy; absent metadata means no compression.
- ECDH-ES protected headers use a deliberately minimal `epk` profile. Only
  `kty`, `crv`, `x`, and `y` are accepted; standalone-JWK metadata such as
  `kid`, `use`, or `alg`, private `d`, and shortened EC coordinates fail
  closed. Coordinates must use the full curve width required by RFC 7518.
- The random source passed to compact-JWE encryption supplies the AES-GCM IV.
  ECDH-ES ephemeral keypairs are generated independently by the cryptographic
  backend's CSPRNG, so deterministic IV injection is not an ECDH test hook.
- Deserialized claim values such as `serde_json::Value` are caller-owned and do not
  zeroize on drop. Use the claims-JSON byte helpers for adapters that need an
  explicit zeroizing owner at the JOSE boundary.
- The wasm lane uses package-owned Rust cryptographic implementations and
  executes the applicable portable JOSE vectors under a JavaScript WASM host.
  The host supplies secure randomness through the Web Crypto integration.
- JWK parsing, validation, and thumbprints are delegated to `reallyme-crypto`;
  this crate only consumes validated key metadata for JOSE policy decisions.
  The upstream native JWK deserializer rejects unrecognized members, including
  `key_ops`, `x5c`, and `ext`. The operation-contract JSON adapter accepts
  additional public members and applies its own operation policy.
- JOSE algorithm policy follows RFC 7515, RFC 7516, RFC 7518, RFC 7519, and
  RFC 8725. The `EdDSA` identifier is bound to Ed25519 key metadata. RFC 9864's
  fully specified `Ed25519` identifier is not yet accepted.

## Unsupported JOSE Features

This crate does not implement RSA JWS/JWE, AES-KW, PBES2, or JWE JSON
serialization. Expanding the supported surface requires explicit algorithms,
tests, and conformance records.

## Operation Execution Boundary

Use `reallyme_jose::wire::execute_operation_v1`
for the canonical binary protobuf entrypoint and `execute_operation_json_v1` for the
generated ProtoJSON request adapter. Both return zeroizing binary
`JoseOperationResponse` bytes. Callers must use
`decode_operation_response_v1` with the submitted `JoseOperationKind`; it requires
response contract V2 and
rejects unknown versions, missing outcomes, malformed errors, and operation
mismatches as typed backend failures.

`JoseOperationRequest` selects exactly one operation. The returned canonical
response selects the same operation and then exactly one generated `result` or
`error` outcome. Failures before a trusted request operation exists use
`boundary_error`; later failures remain under the selected operation.

The versioned entrypoints above are the only executable wire contract,
preventing adapters from inferring
an operation or error branch from untyped payload bytes.

The `wire` module deliberately exposes `reallyme-jose-proto` generated message
and enum types. Treat that dependency as the adapter ABI for a given published
release, but not as the preferred application SDK surface. Pre-1.0 minor
releases may intentionally revise the schema, so adapters should keep the
protobuf and Rust crates on the same release line.

JWT wire header policy is presence-sensitive. Omitting the policy requires an
explicit `typ: JWT` header. An explicit policy may accept missing `typ` for a
legacy issuer by setting `allow_missing_typ` to true.

JWT wire temporal validation is also explicit. A verify request selects one
`verification.mode`: `signature_only`, `claims`, or `temporal_only`.
Time-validating modes require a valid current time and bounded skew; omitting
the mode fails closed. JWT signing's optional `header_options` distinguishes
the default JWT type, an explicitly omitted type, and a caller-selected type.
An empty selected type is rejected.

JWE decrypt requests expose the native protected-header policy at the wire
boundary. Adapters can require `kid` and bind exact `kid`, `typ`, `cty`, `apu`,
and `apv` values. Presence wrapper messages distinguish an omitted expectation
from an explicitly expected empty value.

The JSON adapter enforces both a representation-specific text limit and the
binary protobuf message limit after decoding. Since byte fields expand in JSON,
large binary payloads are more efficient through the binary protobuf lane.

This crate does not define or run an RPC service. FFI, JNI, WASM, Swift,
Kotlin, TypeScript, or external transport wrappers should remain thin owners of
transport concerns and delegate operation execution to the canonical wire lane.

## References

- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7516: JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html)
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 9864: Fully-Specified Algorithms for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9864.html)

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your
option. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.

## Caller-owned compact JWS providers

Use `jws::sign_compact_jws_with_provider` when the caller supplies the exact
protected-header JSON and controls the signing key. The generated
`JoseJwsSignWithProviderRequest` binds the chosen asymmetric registration and
can tighten the compact size limit. The callback returns the JOSE wire
signature bytes for that registration.

`jws::verify_compact_jws_with_provider` passes the selected registration, exact
received signing input and decoded parts to the verifier. The caller must
authorize the algorithm and verification key. An explicitly permitted public
`jwk` header is profile data and does not establish trust. The API produces an
authenticated result only when the callback succeeds. For parsing alone,
`jws::inspect_compact_jws` returns unauthenticated parts.
