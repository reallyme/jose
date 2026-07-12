<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-jose

`reallyme-jose` provides compact JOSE, JWT, JWS, and JWE helpers for ReallyMe
identity workflows.

The crate keeps the JOSE policy layer separate from lower-level primitives:

- cryptographic operations go through `reallyme-crypto`;
- the exact `Algorithm` type used by JWT/JOSE helpers is re-exported from this
  crate, so consumers do not need a separate `reallyme-crypto-core` dependency;
- codec operations go through `reallyme-codec`.

## Install

```toml
[dependencies]
reallyme-jose = "0.1"
```

## Security Model

- JWT verification binds the token header algorithm to the supplied JWK
  algorithm and curve metadata.
- Compact JWS, signed JWT, and compact JWE parsing reject duplicate protected
  header members before policy evaluation.
- `crit`, `zip`, `jku`, embedded `jwk`, `x5u`, and `x5c` protected-header
  parameters are not supported and fail closed.
- JWK parsing, validation, and thumbprints are delegated to `reallyme-crypto`;
  this crate only consumes validated key metadata for JOSE policy decisions.
- JOSE algorithm policy follows RFC 7515, RFC 7516, RFC 7518, RFC 7519,
  RFC 8725, and RFC 9864. The current `EdDSA` support is bound to Ed25519 key
  metadata and is not treated as an open-ended polymorphic choice.

## Unsupported JOSE Features

This crate does not implement RSA JWS/JWE, AES-KW, PBES2, or JWE JSON
serialization. Expanding the supported surface requires explicit algorithms,
tests, and conformance records.

## References

- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7516: JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html)
- [RFC 7518: JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html)
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 9864: Fully-Specified Algorithms for JOSE and COSE](https://www.rfc-editor.org/rfc/rfc9864.html)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

## Copyright And Trademarks

Copyright © 2026 by ReallyMe LLC.

ReallyMe<sup>®</sup> is a registered trademark of ReallyMe LLC.
