# reallyme-jose

Compact JWS, JWT, and JWE operations for Rust. The default feature is `native`;
WASM builds use `--no-default-features --features wasm`. The wasm lane uses
package-owned Rust cryptographic implementations and host-provided randomness.
RSA JWS/JWE, AES-KW, PBES2, and JWE JSON serialization are unsupported.

## Install

```toml
[dependencies]
reallyme-jose = "0.5.2"
```

`Algorithm` is re-exported for callers selecting JWT algorithms.
`api::contract` re-exports the generated types included by both runtime lanes.
Use `api::execute` for generated requests or `api::execute_with_providers` with
a caller-owned provider context. Keep `reallyme-jose-proto` on the same release
line; pre-1.0 minor releases may change the operation contract.

## JWK thumbprints

`jwk::thumbprint_sha256` accepts borrowed
`JwkThumbprintMembers::{Ec, Okp, Rsa, Oct}` members and returns a
`Zeroizing<[u8; 32]>` RFC 7638 SHA-256 digest. Only required members are included,
in lexicographic order. Members must be nonempty and at most 8,192 UTF-8 bytes
before JSON escaping. Callers may enforce stricter limits.

Supply already-encoded JWK text. This function does not normalize encodings,
validate curves, or validate cryptographic keys. The JSON adapter,
`jwk::thumbprint_sha256_from_json`, ignores extra fields; callers must handle
parsing, duplicate members, input limits, and cleanup of the JSON object.
Quotes, backslashes, and control characters are JSON-escaped; RFC 7638 section
3.3 specifies only unescaped values. Errors use `JwkThumbprintErrorReason`.
Canonical JSON and digest owners zeroize on drop; borrowed inputs remain
caller-owned.

## Verification and encryption requirements

- Unsigned JWT decoding does not authenticate the sender. Signed JWT verification
  binds the header algorithm to the supplied JWK metadata and public key.
- Compact protected headers and verified claims JSON reject duplicate members.
  `b64`, `crit`, `jku`, and `x5u` protected headers are unsupported. A policy that
  permits embedded `jwk` or `x5c` does not authorize those keys or certificates;
  bind accepted metadata to the verification key supplied by the caller.
- ES256 accepts otherwise valid high-S signatures. Use validated claims and
  issuer-controlled identifiers for token identity. ES256K requires low-S
  signatures. `EdDSA` selects Ed25519; the `Ed25519` JOSE label is unsupported.
- JWT NumericDate values must be positive integral seconds. Zero, negative,
  and fractional values are rejected. Select an explicit verification mode and
  supply the current time for modes that validate time claims.
- Direct JWE encryption generates a fresh 96-bit IV. Callers must enforce the
  AES-GCM per-key invocation budget and rotate CEKs before the applicable limit.
  Count repeated encryption calls, including any sizing and write calls made
  through caller-owned FFI buffers.
- JWE authentication does not establish sender identity. Verify an independent
  signature or use a key-distribution protocol that authenticates the sender.
- ECDH-ES `epk` accepts only `kty`, `crv`, `x`, and `y`; coordinates must have
  the full curve width. ECDH-ES P-384 and P-521 are unavailable in WASM. The
  supplied random source controls JWE IVs, not backend-generated ephemeral keys.
- `serde_json::Value` and other deserialized claims do not zeroize on drop.
  Prefer the claims-JSON byte helpers when an explicit zeroizing owner is needed,
  and clear caller-owned key, claims, and plaintext buffers after use.

Compression is opt-in through the typed `DEF` policy. Raw DEFLATE runs before
encryption; decryption authenticates the tag before inflating and caps output
at 1 MiB. Do not mix secrets with attacker-controlled values when ciphertext
length is observable. Codec workspaces and allocator copies may retain data;
leave compression disabled when strict erasure is required. OpenID4VCI adapters
may advertise `zip_values_supported: ["DEF"]` only when compression is enabled.
See the repository [security policy](../../SECURITY.md) for reporting and
integration precautions.

## Caller-owned compact JWS providers

Use `jws::sign_compact_jws_with_provider` when the caller supplies the exact
protected-header JSON and controls the signing key. The generated
`JoseJwsSignWithProviderRequest` selects the asymmetric registration and can
restrict compact size. Return JOSE wire signature bytes from the callback.

`jws::verify_compact_jws_with_provider` passes the selected registration, exact
signing input, and decoded parts to the verifier. The caller must authorize the
algorithm and key. An allowed public `jwk` header does not establish trust.
Verification succeeds only when the callback succeeds.
`jws::inspect_compact_jws` returns unauthenticated parts for parsing alone.

## Operation Execution Boundary

`wire::execute_operation_v1` accepts binary protobuf;
`wire::execute_operation_json_v1` accepts generated ProtoJSON. Both return
binary `JoseOperationResponse` bytes. Owned wire outputs use zeroizing buffers.
Decode them with `decode_operation_response_v1` and the submitted
`JoseOperationKind`; it requires response contract V2 and rejects mismatched
operations, unknown versions, missing outcomes, and malformed errors.

A response selects the requested operation and one `result` or `error` outcome.
Failures before operation selection use `boundary_error`; later failures remain
under the selected operation. Generated types and field semantics are described
in the [protobuf crate](../proto/README.md). The `wire` module exposes those
message and enum types; adapters must use a compatible protobuf crate version.

JWT wire header policy is presence-sensitive. Omitting it requires `typ: JWT`;
set `allow_missing_typ` in an explicit policy to accept a legacy issuer without
that header. JWT signing's optional `header_options` distinguishes the default
JWT type, an omitted type, and a caller-selected type; an empty type is rejected.

JWT verification selects `signature_only`, `claims`, or `temporal_only` in
`verification.mode`. Claims validation binds audience and optional issuer or
subject. Temporal-only validation checks time claims without authorizing the
recipient. Time-validating modes require a valid current time and bounded skew.

JWE decrypt policy can require `kid` and bind exact `kid`, `typ`, `cty`, `apu`,
and `apv` values. Presence wrappers distinguish an omitted expectation from an
explicitly expected empty value. JSON requests have a text limit as well as the
decoded binary-message limit; use binary protobuf for large byte payloads.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your
option. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
