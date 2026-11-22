# reallyme-jose-proto

Generated Buffa message, view, and ProtoJSON bindings for the ReallyMe JOSE
operation contract. This crate defines messages only; it provides no RPC
service or transport. Use the matching `reallyme-jose` release to execute them.

## Install

```toml
[dependencies]
reallyme-jose-proto = { version = "0.6.0", features = ["generated"] }
```

## Requests and responses

1. Select one operation in the `JoseOperationRequest` oneof.
2. Pass its binary protobuf or generated ProtoJSON encoding to the embedding
   adapter's V1 execution function.
3. Decode the operation-discriminated response, `JoseOperationResponse`.
   Require contract version V2, match the requested operation, and handle its
   generated `result` or `error` outcome.

Responses are binary protobuf for both request encodings. Failures before
operation selection use `boundary_error`; later failures remain under the
selected operation. `JoseError` distinguishes `primitive`, `provider`, and
`backend` branches with typed reason codes. Use generated algorithm enums;
their protobuf numbers are not JOSE registry identifiers.

ABI V1 entrypoints require response contract V2. Earlier wire semantics are
unsupported. Regenerate bindings and rebuild native/WASM binaries and SDKs
together when updating the contract.

Generated Rust enums and oneofs are exhaustive. Schema additions that pass
the protobuf compatibility check can still require new downstream Rust match
arms. Native selector views are non-exhaustive and require a wildcard arm.

JWT signing uses `header_options`: omission defaults to `typ: JWT`; a present
message without `typ` omits the header; a present empty `typ` is rejected.
JWT verification requires one `verification.mode`: `signature_only`, `claims`,
or `temporal_only`. Retired and unknown request fields are rejected.

JWE decrypt requests include a presence-sensitive protected-header policy.
Require `kid` or bind exact `kid`, `typ`, `cty`, `apu`, and `apv` values through
that policy. Wrappers distinguish absent expectations from explicitly empty
ones. `JWE_HEADER_POLICY_MISMATCH` covers `typ` and `cty`; `kid`, `apu`, and
`apv` have separate reasons.

Compact JWS accepts EdDSA and ES256; JWT also accepts ES256K. Unsupported
operation/algorithm combinations return a typed error. Provider capability
handles are process-local and require a caller-owned provider context.

## Sensitive data and decoding

Generated messages can contain private keys, CEKs, claims, plaintext, and
correlating metadata. Do not log them. `SecretBytes` and `SecretString` use
`secrecy` ownership and clear their allocations on drop; cloned values own
separate allocations. Caller-owned inputs and managed-runtime copies require
separate cleanup.

Decode untrusted input with `DecodeOptions::reject_unknown_fields()` and
application size/depth limits. Disabling unknown-field storage alone does not
reject unknown wire fields. Apply JSON admission checks before decoding raw
JSON. A null collection is absent; repeated strings reject null elements.
For in-place updates, use `DecodeOptions::clear_on_merge_error()` to clear the
entire destination after a failed merge, including previously stored values.

Borrowed views require the input buffer to remain alive for the view's lifetime.
Keep sensitive inputs in a wipe-owning buffer. For owned wire storage, use
`buffa::sensitive::GuardedOwnedView` with unknown-field rejection and resource
limits. `from_owned` encodes into guarded storage; `decode` copies into it and
leaves the original input with the caller.

## Regeneration

Generated code is checked in. Run these commands from the repository root:

```sh
cargo install reallyme-protoc-gen-buffa --version '=0.1.3' --locked
cargo install reallyme-protoc-gen-buffa-packaging --version '=0.1.3' --locked
node scripts/generate-jose-proto.mjs
buf lint
buf breaking --against crates/proto/compatibility/v2.binpb
```

Keep the V2 compatibility descriptor unchanged during routine generation.
Contract changes must pass the compatibility check or receive a separately
reviewed version and checkpoint.

Contributors should follow the
[Engineering Philosophy](https://github.com/reallyme/.github/blob/main/ENGINEERING_PHILOSOPHY.md)
and [Architecture Standards](https://github.com/reallyme/.github/blob/main/ARCHITECTURE.md).

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your
option. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
