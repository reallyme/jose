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

## Boundary Contract

The schema defines `JoseOperationRequest` as the single executable request
message and `JoseProtoResultEnvelope` as the single result envelope. Envelope
bytes contain either operation-specific result protobuf bytes or structured
`JoseError` protobuf bytes.

The intended adapter flow is:

1. Encode one operation in the `JoseOperationRequest` `oneof`.
2. Call the embedding adapter's process-proto function with those request bytes.
3. Decode `JoseProtoResultEnvelope.status`, then decode `payload` as either the
   selected operation's result type or `JoseError`.

The JSON request representation uses these same generated messages. The
`reallyme-jose` `process_json` entrypoint still returns the binary protobuf
result envelope; adapters that require JSON output convert the structured
result separately. The JSON request path does not define different JOSE
behavior.

`JoseError` preserves the public error branch:

- `primitive` for caller input, JOSE primitive, or policy failures;
- `provider` for unsupported algorithms, unavailable providers, and randomness
  failures;
- `backend` for protobuf, JSON, dispatch, FFI, WASM, and internal failures.

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
reallyme-jose-proto = { version = "0.2.0", features = ["generated"] }
```

## License

Licensed under the Apache License, Version 2.0.

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
