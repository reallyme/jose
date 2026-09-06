# `@reallyme/jose`

Production TypeScript bindings for the ReallyMe JOSE operation contract. JWS,
JWT, and JWE operations execute in the same Rust implementation used by the
Rust, Swift, Kotlin/JVM, and Android packages.

## Provider setup

The following Node.js example loads the packaged WASM asset directly:

```ts
import { readFile } from "node:fs/promises";
import {
  ReallyMeJose,
  installReallyMeJoseWasmProvider,
} from "@reallyme/jose";
import * as wasm from "@reallyme/jose/wasm/reallyme_jose_wasm.js";

const module = await readFile(new URL(
  import.meta.resolve("@reallyme/jose/wasm/reallyme_jose_wasm_bg.wasm"),
));
wasm.initSync({ module });
installReallyMeJoseWasmProvider(wasm);

const claimsJsonBytes = new TextEncoder().encode('{"sub":"example"}');
try {
  const compact = ReallyMeJose.encodeUnsignedJwt(claimsJsonBytes);
  // This parses an unsigned JWT; it does not authenticate its claims.
  const decoded = ReallyMeJose.decodeUnsignedJwt(compact);
  decoded.fill(0);
} finally {
  claimsJsonBytes.fill(0);
}
```

In a browser, serve the exported `.wasm` asset through your bundler, read it
into a `Uint8Array`, and call `wasm.initSync({ module: bytes })` before provider
installation. Node.js integrations require version 20.19 or newer.

Provider installation is explicit. Calls fail closed when no WASM provider is
installed; applications must select a trusted module. Sensitive inputs are
copied into bounded owners and cleared after dispatch; callers remain
responsible for clearing their own `Uint8Array` values.

The WASM provider supports compact JWS with EdDSA and ES256, JWT with EdDSA,
ES256, and ES256K, direct-key JWE with A128GCM/A192GCM/A256GCM, and ECDH-ES
P-256. ECDH-ES P-384 and P-521 fail closed with the typed
`providerUnsupported` reason; no JavaScript or ambient-provider fallback is
performed.

## Raw WASM Module Contract

The raw module exposes `executeOperation` and `executeOperationJson` as its
operation entrypoints, alongside WASM initialization exports.
Direct raw WASM calls are unsupported for application logic. Applications
should use `ReallyMeJose`, whose generated protobuf decoding, response-shape
validation, typed errors, size limits, and cleanup rules form the supported
API. Cryptographic operations stay inside WASM; the host supplies secure
randomness.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your
option. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
