<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-jose

`reallyme-jose` provides compact JOSE, JWT, JWS, and JWE helpers for ReallyMe
identity workflows.

The crate keeps the JOSE policy layer separate from lower-level primitives:

- cryptographic operations go through `reallyme-crypto`;
- the exact `Algorithm` type used by JWT/JOSE helpers is re-exported from this
  crate, so consumers do not need a separate `reallyme-crypto-core` dependency;
- codec operations go through `reallyme-codec`.

The companion `reallyme-jose-proto` crate publishes the generated protobuf
types used by the optional `wire` feature. It is versioned with this crate so
FFI, WASM, Swift, Kotlin, TypeScript, and generated-SDK adapters can share one
transport-neutral process-proto contract. It does not define a network or RPC
protocol; the embedding adapter owns transport and lifecycle concerns. The
feature is opt-in, so native SDK users do not compile Buffa or generated
protobuf code by default.

## Install

```toml
[dependencies]
reallyme-jose = "0.2.0"
```

## Security Model

- JWT verification binds the token header algorithm to the supplied JWK
  algorithm and curve metadata, the JWK `kid` when present, and the caller's
  public-key bytes.
- Unsigned JWT decoding is parsing only; it does not authenticate the sender.
- The protobuf wire boundary returns either result payload bytes or structured
  `JoseError` payload bytes in a `JoseProtoResultEnvelope`; the error branch and exact
  `JoseErrorReason` are preserved end-to-end.
- Owned wire outputs use zeroizing buffers because result bytes can contain
  claims JSON, decrypted plaintext, or structured error bytes.
- Compact JWS, signed JWT, and compact JWE parsing reject duplicate protected
  header members before policy evaluation.
- Unsigned JWT parsing and verified claims JSON also reject duplicate object
  members so mixed deployments cannot disagree on first-wins versus last-wins
  claim interpretation.
- `crit`, `zip`, `jku`, embedded `jwk`, `x5u`, and `x5c` protected-header
  parameters are not supported and fail closed.
- ES256 verification accepts otherwise valid high-S signatures as RFC 7515
  permits; applications should not use compact-token byte equality as an
  issuer-independent uniqueness guarantee. Face ID and Secure Enclave protected
  P-256 signers may produce canonical signatures, but verifier acceptance is
  based on JOSE/P-256 ECDSA validity rather than that platform-specific emission
  detail.
- Deserialized claim values such as `serde_json::Value` are caller-owned and do not
  zeroize on drop. Use the claims-JSON byte helpers for adapters that need an
  explicit zeroizing owner at the JOSE boundary.
- The wasm lane depends on host-provider P-256 decompression and ECDH imports
  to reject malformed, off-curve, or wrong-length SEC1 points before returning
  key material.
- JWK parsing, validation, and thumbprints are delegated to `reallyme-crypto`;
  this crate only consumes validated key metadata for JOSE policy decisions.
- JOSE algorithm policy follows RFC 7515, RFC 7516, RFC 7518, RFC 7519,
  RFC 8725, and RFC 9864. The current `EdDSA` support is bound to Ed25519 key
  metadata and is not treated as an open-ended polymorphic choice.

## Unsupported JOSE Features

This crate does not implement RSA JWS/JWE, AES-KW, PBES2, or JWE JSON
serialization. Expanding the supported surface requires explicit algorithms,
tests, and conformance records.

## Process-Proto Boundary

With the `wire` feature enabled, use `reallyme_jose::wire::process_proto` for
the single binary protobuf entrypoint and `process_json` for the
proto3-compatible JSON adapter. Both return zeroizing envelope bytes. The
lower-level `process_*_output` helpers return a structured `JoseProtoOutput`
when an adapter needs to inspect the status before serializing the envelope.
`process_json` changes request decoding only: its response remains the binary
protobuf envelope. Use `jose_proto_output_to_json` when the host contract
requires a JSON result envelope.

`JoseOperationRequest` selects exactly one operation. The returned
`JoseProtoResultEnvelope` identifies whether its payload bytes encode the
operation-specific result or a structured `JoseError`. Malformed input and
expected validation failures use this same envelope model rather than
transport-specific exceptions or status codes.

The `wire` module deliberately exposes `reallyme-jose-proto` generated message
and enum types. Treat that dependency as the adapter ABI for a given published
release, but not as the preferred application SDK surface. Pre-1.0 minor
releases may intentionally revise the schema, so adapters should keep the
protobuf and Rust crates on the same release line.

JWT wire header policy is presence-sensitive. Omitting the policy uses the
standard verifier behavior; explicitly sending a default policy is stricter
because protobuf boolean defaults set `allow_missing_typ` to false.

JWT wire temporal validation is also explicit. A verify request must either set
`signature_only` or provide `temporal_policy` with a nonzero
`temporal_policy.now_unix`; omitting both fails closed instead of silently
selecting weaker validation.

JWE decrypt requests expose the native protected-header policy at the wire
boundary. Adapters can require `kid` and bind exact `kid`, `typ`, `cty`, `apu`,
and `apv` values. Presence wrapper messages distinguish an omitted expectation
from an explicitly expected empty value.

The JSON adapter enforces both a representation-specific text limit and the
binary protobuf message limit after decoding. Since byte fields expand in JSON,
large binary payloads are more efficient through the binary protobuf lane.

This crate does not define or run an RPC service. FFI, JNI, WASM, Swift,
Kotlin, TypeScript, or external transport wrappers should remain thin owners of
transport concerns and delegate operation execution to the process-proto lane.

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
