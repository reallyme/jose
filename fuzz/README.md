<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Fuzzing Harnesses

Coverage-guided libFuzzer targets exercise JOSE compact serializations as
untrusted input. Each target asserts the same baseline property: arbitrary input
must fail closed with typed errors and must not panic, overflow, read out of
bounds, or run unbounded.

The fuzz crate lives outside the main Cargo workspace. It declares an empty
`[workspace]` because `libfuzzer-sys` uses a `#![no_main]` runtime that is not
compatible with the production crate's strict lint configuration.

## Targets

| Target | Parser under test |
| --- | --- |
| `compact_jwe` | compact JWE direct decryption parser and protected-header policy |
| `compact_jws_es256` | compact JWS ES256 parser and protected-header policy |
| `signed_jwt` | signed JWT parser, duplicate-header guard, and ES256 key binding |
| `unsigned_jwt` | unsigned JWT parser and `alg = "none"` policy |

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cargo +nightly fuzz build
cargo +nightly fuzz run compact_jwe -- -max_total_time=60
cargo +nightly fuzz run signed_jwt -- -max_total_time=60
```

Reproduce a crash artifact with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) and
[NOTICE](../NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
