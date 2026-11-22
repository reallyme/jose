# `@reallyme/jose`

JWS, JWT, and JWE operations for TypeScript through a Rust/WASM provider.
Node.js integrations require version 20.19 or newer.

## Provider setup

Install with `npm install @reallyme/jose`. This Node.js example loads the packaged
WASM asset:

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
  // Parsing an unsigned JWT does not authenticate its claims.
  const decoded = ReallyMeJose.decodeUnsignedJwt(compact);
  decoded.fill(0);
} finally {
  claimsJsonBytes.fill(0);
}
```

In a browser, serve the exported `.wasm` asset through your bundler, read it
into a `Uint8Array`, and call `wasm.initSync({ module: bytes })` before installing
the provider. Select a trusted module. Calls made without an installed provider
return the local `provider-not-installed` SDK code.

The provider supports EdDSA/ES256 compact JWS, EdDSA/ES256/ES256K JWT,
direct-key JWE with A128GCM/A192GCM/A256GCM, and ECDH-ES P-256. ECDH-ES P-384
and P-521 return `providerUnsupported`.

JWT verification requires `verification: { mode: "signatureOnly" }`,
`{ mode: "claims", policy }`, or `{ mode: "temporalOnly", policy }`.
`ReallyMeJoseJwtClaimsPolicy` binds audience and optional issuer/subject;
`ReallyMeJoseJwtTemporalPolicy` checks time claims only. The default temporal
preset requires expiration and allows 60 seconds of skew. Options accept plain
or null-prototype records; unknown fields and modes are rejected.

The facade clears its owned request and response arrays. Callers must clear
their own sensitive `Uint8Array` values. JavaScript and protobuf runtime copies
cannot guarantee memory erasure.

## Raw WASM Module Contract

The raw module exports `executeOperation` and `executeOperationJson` plus
initialization functions. Direct raw WASM calls are unsupported for application
logic; use `ReallyMeJose` for response validation, typed errors, limits, and
buffer cleanup.

## License

Licensed under either the MIT License or the Apache License, Version 2.0, at your
option. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
