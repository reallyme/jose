<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-jose-proto

`reallyme-jose-proto` contains the generated Buffa bindings for the versioned
ReallyMe JOSE protobuf boundary.

The crate is intentionally small: it publishes the checked-in generated message,
view, JSON, and protobuf encoding types used by `reallyme-jose` wire helpers.
The `reallyme-jose` `wire` feature is opt-in, so normal native SDK users do not
compile Buffa or generated protobuf code by default. This crate does not run a
RPC service and does not own JOSE cryptographic behavior.

The schema exists to give FFI, WASM, mobile, generated-SDK, and process
boundaries one deterministic request/result representation without duplicating
JOSE policy or dispatch logic in every language. It defines messages only: no
protobuf `service`, network transport, endpoint, streaming, or discovery
contract is part of this crate.

This crate defines messages only; it intentionally declares no protobuf service.

## Boundary Contract

The schema defines `JoseOperationRequest` as the single executable request and
`JoseOperationResponse` as the canonical versioned response. Generated oneofs
identify the selected operation and its `result` or `error` outcome without an
opaque nested payload.

The intended adapter flow is:

1. Encode one operation in the `JoseOperationRequest` `oneof`.
2. Call the embedding adapter's V1 operation execution function with those bytes.
3. Decode `JoseOperationResponse`, require contract version V1, require the
   operation variant to match the request, and handle its generated outcome.

Malformed input before operation selection uses `boundary_error`. Semantic,
provider, and backend failures after selection remain nested beneath the
selected operation. The JSON request representation is generated ProtoJSON;
canonical results remain binary protobuf and have identical meaning across the
binary and JSON request paths.

ProtoJSON changes request decoding only; canonical results remain binary protobuf.
FFI, JNI, Swift, Kotlin, and Android adapters all use the versioned,
operation-discriminated response and never infer result types from opaque
payload bytes.

Algorithm selectors use family-local numeric bands aligned with the
corresponding `reallyme-crypto-proto` families where the algorithms overlap:
EdDSA is in the 100 band, elliptic-curve suites in the 200 band, and AES-GCM
content encryption at 100/110/120. These are protobuf identifiers, not JOSE
registry values. The compact pre-release values are reserved so old request
bytes fail closed instead of being silently reinterpreted.

`JoseError` preserves the public error branch:

- `primitive` for caller input, malformed protobuf or JSON, JOSE primitive, or
  policy failures;
- `provider` for unsupported algorithms, unavailable providers, and randomness
  failures;
- `backend` for serialization, key-derivation, and internal implementation
  failures after a request has crossed the boundary.

Several request and result fields carry private keys, direct CEKs, claims JSON,
plaintext, or correlating protocol metadata. Generated-SDK and host adapters
must treat those bytes as sensitive, avoid logging them, and zeroize owned
buffers after use.

JWE decrypt requests include a presence-sensitive protected-header validation
policy. `kid` can be required, and exact `kid`, `typ`, `cty`, `apu`, and `apv`
values can be bound to the protocol context. Message wrappers preserve the
difference between an absent expectation and an explicitly expected empty
value.

The protobuf and Rust crates are released as one versioned boundary. Pre-1.0
minor releases may intentionally change message contracts; consumers should
regenerate adapters and update both crates together. CI enforces schema linting
and checked-in generated-code freshness rather than compatibility with earlier
pre-1.0 releases.

Generated code is checked in rather than produced by `build.rs`. Refresh it with
the repository-level `buf.gen.yaml`:

```sh
buf generate
cargo fmt --package reallyme-jose-proto
```

## Install

```toml
[dependencies]
reallyme-jose-proto = { version = "0.3.0", features = ["generated"] }
```

## License

Licensed under the Apache License, Version 2.0.

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
