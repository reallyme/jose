# ReallyMe JOSE for Swift

`ReallyMeJOSE` provides JWS, JWT, and JWE operations for Swift 6.3, macOS 13,
and iOS 16 or newer.

## Install

```swift
.package(
  url: "https://github.com/reallyme/jose",
  "0.6.0"..<"0.7.0"
)
```

Add the product to your target:

```swift
.product(name: "ReallyMeJOSE", package: "jose")
```

The package includes the checksum-bound native XCFramework. Applications that
encode the operation contract directly can also add:

```swift
.product(name: "ReallyMeJOSEProto", package: "jose")
```

Use `ReallyMeJOSEError` to handle failures. `verifyJWT` requires an explicit
`verification`: `.signatureOnly`, `.claims(ReallyMeJOSEJWTClaimsPolicy(...))`,
or `.temporalOnly(ReallyMeJOSEJWTTemporalPolicy(...))`. Claims validation binds
audience and optional issuer/subject; temporal-only validation does not establish
recipient authorization.

Use `[UInt8]` for keys, claims, JWK JSON, and plaintext, and clear caller-owned
buffers after use. SDK-owned request and response buffers are cleared. Swift
strings, SwiftProtobuf internals, copy-on-write aliases, and runtime copies
cannot guarantee memory erasure.

## Source-tree testing

From the repository root on macOS:

```sh
scripts/test_swift_source_tree.sh
```

Runtime loading is an explicit integration/testing mode. It requires
`REALLYME_JOSE_SWIFTPM_RUNTIME_FFI=1`, the local `.reallyme-jose-runtime-ffi`
marker, and a native library selected through `REALLYME_JOSE_FFI_LIBRARY_PATH`
or the local debug path. Published packages use the linked XCFramework;
runtime loading does not substitute for an unavailable release artifact.

## License

Licensed under either the [MIT License](../../LICENSE-MIT) or the
[Apache License, Version 2.0](../../LICENSE-APACHE), at your option. See
[NOTICE](../../NOTICE).
