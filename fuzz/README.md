# Fuzzing Harnesses

Coverage-guided libFuzzer targets exercise JOSE compact serializations as
untrusted input. Each target asserts the same baseline property: invalid input
must fail closed with typed errors and must not panic, overflow, read out of
bounds, or run unbounded.

The fuzz crate lives outside the main Cargo workspace. It declares an empty
`[workspace]` because `libfuzzer-sys` uses a `#![no_main]` runtime that is not
compatible with the production crate's strict lint configuration.

## Targets

| Target | Parser under test |
| --- | --- |
| `compact_jwe` | compact JWE direct decryption parser and protected-header policy |
| `compact_jwe_ecdh_es` | compact JWE ECDH-ES protected-header, `epk`, point validation, and Concat-KDF path |
| `parse_jwe_header` | public compact-JWE protected-header deserialization, duplicate members, dangerous extensions, and minimal `epk` profile |
| `compact_jws_es256` | compact JWS ES256 parser and protected-header policy |
| `signed_jwt` | signed JWT parser, duplicate-header guard, and ES256 key binding |
| `validate_jwt_temporal` | authenticated temporal-claim values, native verification time, and temporal-policy boundaries |
| `unsigned_jwt` | unsigned JWT parser and `alg = "none"` policy |
| `operation_wire` | canonical binary protobuf and generated ProtoJSON execution, including every operation-contract semantic adapter |
| `operation_response` | untrusted canonical V1 response decoding, operation discrimination, nested outcome validation, and cross-operation rejection |
| `ffi_operation` | C ABI request/output pointer, length, aliasing, ABI-version, capacity, panic-firewall, and cleanup boundary |

Seed corpora live under `fuzz/corpus/<target>/`. The JOSE dictionary in
`fuzz/dictionaries/jose.dict` gives libFuzzer compact-serialization and header
tokens so short scheduled runs do not need to discover Base64URL-shaped inputs
from scratch.

## Running

```sh
rustup toolchain install nightly-2026-07-01
cargo install cargo-fuzz --version 0.13.2 --locked

cargo +nightly-2026-07-01 fuzz build
cargo +nightly-2026-07-01 fuzz run compact_jwe -- -max_total_time=60
cargo +nightly-2026-07-01 fuzz run compact_jwe_ecdh_es -- -max_total_time=60 -dict=fuzz/dictionaries/jose.dict
cargo +nightly-2026-07-01 fuzz run signed_jwt -- -max_total_time=60
cargo +nightly-2026-07-01 fuzz run operation_wire -- -max_total_time=60 -dict=fuzz/dictionaries/jose.dict
cargo +nightly-2026-07-01 fuzz run operation_response -- -max_total_time=60
cargo +nightly-2026-07-01 fuzz run ffi_operation -- -max_total_time=60
```

Reproduce a crash artifact with:

```sh
cargo +nightly-2026-07-01 fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your
option. See [LICENSE](../LICENSE) and
[NOTICE](../NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
