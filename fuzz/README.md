# Fuzzing

Run targets from the repository root. The fuzz crate is outside the main Cargo
workspace and uses the pinned nightly toolchain below.

| Target | Input or operation |
| --- | --- |
| `compact_jwe` | Direct JWE and protected-header policy |
| `compact_jwe_ecdh_es` | ECDH-ES headers, `epk`, key agreement, and Concat-KDF |
| `parse_jwe_header` | JWE protected-header JSON |
| `compact_jws_es256` | ES256 compact JWS |
| `signed_jwt` | Signed JWT headers and key binding |
| `validate_jwt_temporal` | NumericDate and temporal-policy boundaries |
| `unsigned_jwt` | Unsigned JWT and `alg = "none"` |
| `operation_wire` | Binary protobuf and ProtoJSON requests |
| `operation_response` | V2 responses, operation matching, and error decoding |
| `ffi_operation` | C ABI pointers, lengths, aliasing, output capacity, and cleanup |

```sh
rustup toolchain install nightly-2026-09-15
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-09-15 fuzz build
cargo +nightly-2026-09-15 fuzz run compact_jwe_ecdh_es -- -max_total_time=60 -dict=fuzz/dictionaries/jose.dict
```

Replace `compact_jwe_ecdh_es` with another target from the table. Seed corpora
are under `fuzz/corpus/<target>/`; `fuzz/dictionaries/jose.dict` supplies JOSE
tokens to libFuzzer.

Reproduce a saved failure with:

```sh
cargo +nightly-2026-09-15 fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

## License

Licensed under either the [MIT License](../LICENSE-MIT) or the
[Apache License, Version 2.0](../LICENSE-APACHE), at your option. See
[NOTICE](../NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe Technologies Limited.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
