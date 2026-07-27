<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe JOSE for Kotlin/JVM

`me.really:jose:0.3.0` is the typed Java and Kotlin/JVM facade for the canonical
ReallyMe Rust JOSE implementation. Generated protobuf classes are packaged as
implementation detail and are not the normal SDK surface.

The package covers EdDSA and ES256 compact JWS, unsigned and signed JWT, and
direct or ECDH-ES compact JWE with AES-GCM. Expected operation failures use
`ReallyMeJoseException.JoseFailure`, preserving the exact Rust-owned branch and
reason code without carrying input, path, provider, or backend text.

## Native loading

Published JARs contain platform native libraries, SHA-256/length sidecars, and
a manifest binding the complete native inventory to the reviewed source SHA.
Those native libraries use the workspace-owned `release-ffi` profile so the
FFI unwind contract cannot be changed by ambient Rust code-generation flags.
The loader selects an exact OS/architecture path, copies through a bounded
buffer into a private owner-restricted directory, verifies the digest with a
timing-safe comparison, makes the extracted file read-only, and performs the
ABI and limit handshake before use. `loadLibrary(path)` is an explicit local
integration/testing path; application code normally uses bundled resources.

## Memory model

Secret and PII inputs use `ByteArray`. The facade copies caller arrays into
owned buffers, wraps those without another protobuf copy where possible, and
clears every owned request, serialized request, serialized response, and policy
array in `finally` blocks. Returned plaintext and claims arrays belong to the
caller and should be cleared promptly.

The JVM cannot promise native-style erasure for `String`, generated protobuf
internals, garbage-collected copies, or JIT/runtime copies. Avoid converting
keys, plaintext, claims, or JWK JSON to strings. Generated messages have
redacted debug output, but the typed facade remains the supported API.
Close `ReallyMeJoseJweHeaderPolicy` after use when it owns party-information
arrays so its defensive copies are cleared promptly.

## Local verification

```sh
packages/kotlin/gradlew -p packages/kotlin test verifyJarContainsNativeResources
```

The build locks dependencies, enforces strict dependency verification, accepts
only HTTPS publication repositories without embedded credentials, and requires
in-memory signing material before remote publication.

Release preflight builds native resources independently on Linux x86-64,
Linux AArch64, macOS x86-64, macOS AArch64, and Windows x86-64. Producer job
digests travel as separate artifacts and are checked again before the JAR is
assembled. `scripts/verify_maven_release_repository.mjs` verifies the JAR,
sources, Javadoc, POM, Gradle module metadata, source SHA, and complete native
inventory from the staged repository. Release promotion downloads those exact
attested bytes, signs them in an isolated keyring, refuses existing remote
coordinates, and compares every published remote file with its staged digest.
