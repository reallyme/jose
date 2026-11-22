# ReallyMe JOSE for Kotlin/JVM

JWS, JWT, and JWE operations for Java and Kotlin on JDK 21. Published JARs
include native libraries for Linux x86-64/AArch64, macOS x86-64/AArch64, and
Windows x86-64.

## Install

```kotlin
repositories { mavenCentral() }
dependencies { implementation("me.really:jose:0.5.2") }
```

The SDK loads the bundled library into an owner-restricted directory and
verifies its digest and ABI before use. `loadLibrary(path)` is an explicit
integration/testing option for a caller-selected native library.

Operation failures use `ReallyMeJoseException.JoseFailure` with a typed branch
and reason. `verifyJwt` requires `ReallyMeJoseJwtVerification.SignatureOnly`,
`Claims(ReallyMeJoseJwtClaimsPolicy(...))`, or
`TemporalOnly(ReallyMeJoseJwtTemporalPolicy(...))`. Claims validation binds
audience and optional issuer/subject; temporal-only validation does not establish
recipient authorization.

Use `ByteArray` for sensitive inputs and avoid converting keys, plaintext,
claims, or JWK JSON to strings. The facade clears its owned request and response
buffers. Returned plaintext and claims arrays belong to the caller and should
be cleared promptly. The JVM cannot promise native-style erasure for strings,
protobuf internals, garbage-collected copies, or JIT/runtime copies.

## Source-tree testing

From the repository root:

```sh
scripts/build_kotlin_native_resource.sh build/kotlin-native-resources
packages/kotlin/gradlew -p packages/kotlin test \
  -Preallyme.jose.nativeResourcesDir="$PWD/build/kotlin-native-resources"
```

## License

Licensed under either the [MIT License](../../LICENSE-MIT) or the
[Apache License, Version 2.0](../../LICENSE-APACHE), at your option. See
[NOTICE](../../NOTICE).
