<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe JOSE C ABI

`reallyme-jose-ffi` is the non-publishable native boundary used by supported
platform packages. It exposes one versioned binary protobuf operation
entrypoint, one generated ProtoJSON request entrypoint returning the same
binary response, authoritative size limits, and caller-owned buffer cleanup.

Callers must invoke `rm_jose_abi_version` and require the exact expected value
before calling or casting any other loaded symbol. Operation calls also receive
the ABI version and fail closed if it differs.

The caller owns input, output, and produced-length storage. Nonempty ranges
must be valid, mutually disjoint allocations. A capacity mismatch changes only
the produced-length value, which reports the exact required response size.
Call `rm_jose_zeroize_buffer` before releasing request or response storage that
may contain private keys, claims, compact tokens, JWK JSON, or plaintext.

Swift and JNI adapters allocate responses with a zero-capacity sizing call and
then execute the request independently into the allocated buffer. The encoded
response length is therefore a versioned ABI invariant: fresh nonces, ephemeral
keys, and signatures may change bytes between calls, but their encoded widths
must remain fixed. A future operation with variable-length randomized output
requires a different allocation contract rather than weakening this check.

C status values describe pointer, capacity, ABI, panic, or other transport
state. JOSE success and typed primitive/provider/backend failures are carried
inside the canonical `JoseOperationResponse`; platform adapters must not infer
semantic errors from the C status alone.

Release artifacts must be built with the workspace `release-ffi` profile,
which fixes `panic=unwind` independently of ambient Cargo flags. The crate
rejects `panic=abort`, and every non-leaf export uses the scoped redacting
panic firewall. Use the checked-in header at `include/reallyme_jose.h`; do not
redeclare symbols independently in a platform package.

The supported Swift dynamic artifact uses `RTLD_LOCAL` and statically links its
Rust runtime. Custom builds that share a Rust standard library across dynamic
images are unsupported and must not unload this image while another component
could retain its process-global panic-hook state.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) and
[NOTICE](../../NOTICE).
