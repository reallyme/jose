<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe JOSE for Swift

`ReallyMeJOSE` is the supported Swift 6.3 facade for macOS 13 and iOS 16. It
routes JWS, JWT, and JWE operations through the versioned Rust C ABI and the
canonical generated operation contract. The package also exposes the generated
operation messages as the separate `ReallyMeJOSEProto` product for applications
that deliberately integrate at the wire boundary.

## Install

```swift
.package(
  url: "https://github.com/reallyme/jose",
  from: "0.3.0"
)
```

```swift
.product(name: "ReallyMeJOSE", package: "jose")
```

Applications that exchange the canonical operation contract directly can also
add the protobuf product:

```swift
.product(name: "ReallyMeJOSEProto", package: "jose")
```

Both products use the same generated message definitions. The typed
`ReallyMeJOSE` facade remains the supported application API.

The SDK completes an exact ABI-version handshake before resolving operational
symbols. A missing image, symbol, provider, algorithm, or malformed native
response fails closed with `ReallyMeJOSEError`; errors never carry claims,
keys, compact tokens, plaintext, raw buffers, paths, or backend text.

Sensitive SDK-owned request and response arrays are cleared through the native
zeroization export, with `memset_s` as a fail-safe. Temporary generated `Data`
fields are cleared on all typed-facade paths. Swift strings, SwiftProtobuf
internals, copy-on-write aliases, and garbage-collected or runtime-created
copies cannot promise Rust-style erasure. The facade minimizes those copies,
prefers `[UInt8]` for keys, claims, JWK JSON, and plaintext, and does not expose
debug descriptions for sensitive domain values.

Runtime-loaded tests use `REALLYME_JOSE_FFI_LIBRARY_PATH` or the local debug
library. Published packages use the checksum-bound `ReallyMeJOSEFFI`
XCFramework automatically; consumers do not need to declare the binary target
separately. Runtime loading is an explicit integration/testing mode and is not
a fallback when the linked release artifact is unavailable.

Source-tree runtime tests must set `REALLYME_JOSE_SWIFTPM_RUNTIME_FFI=1` and
create the ignored `.reallyme-jose-runtime-ffi` marker. Requiring both controls
prevents an inherited environment variable from silently removing the linked
binary target for public consumers.

Maintainers bind a freshly built local XCFramework with
`scripts/prepare_swift_binary_manifest.mjs` and its repository-relative
`--local-artifact-path` option. Release verification rejects that override,
recomputes the archive checksum, inspects every native slice for the required C
ABI symbols, and requires the public manifest to bind the exact version and
checksum. `scripts/prepare_swift_release_candidate.sh 0.3.0` performs the full
build-and-bind preparation locally.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) and
[NOTICE](../../NOTICE).
