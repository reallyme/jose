<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# `@reallyme/jose`

Production TypeScript bindings for the ReallyMe JOSE operation contract. JWS,
JWT, and JWE operations execute in the same Rust implementation used by the
Rust, Swift, Kotlin/JVM, and Android packages.

## Provider setup

```ts
import {
  ReallyMeJose,
  installReallyMeJoseWasmProvider,
} from "@reallyme/jose";
import init, * as wasm from "@reallyme/jose/wasm/reallyme_jose_wasm.js";

await init();
installReallyMeJoseWasmProvider(wasm);

const compact = ReallyMeJose.encodeUnsignedJwt(claimsJsonBytes);
```

Provider installation is explicit. Calls fail closed when no reviewed WASM
provider is installed. Sensitive inputs are copied into bounded owners and
cleared after dispatch; callers remain responsible for clearing their own
`Uint8Array` values.

The WASM provider supports compact JWS with EdDSA and ES256, JWT with EdDSA,
ES256, and ES256K, direct-key JWE with A128GCM/A192GCM/A256GCM, and ECDH-ES
P-256. ECDH-ES P-384 and P-521 fail closed with the typed
`providerUnsupported` reason; no JavaScript or ambient-provider fallback is
performed.

## Raw WASM Module Contract

The raw module exports only `executeOperation` and `executeOperationJson`.
Direct raw WASM calls are unsupported for application logic. Applications
should use `ReallyMeJose`, whose generated protobuf decoding, response-shape
validation, typed errors, size limits, and cleanup rules form the supported
API. The module has no ambient global crypto-provider functions.
