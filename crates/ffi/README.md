# ReallyMe JOSE C ABI

Use `include/reallyme_jose.h` for declarations and status codes. Call
`rm_jose_abi_version` and require the expected value before resolving or calling
other operational symbols. Execution calls also take the expected ABI version.
Binary protobuf and ProtoJSON requests both return binary
`JoseOperationResponse` bytes.

## Owned responses

Use `rm_jose_execute_owned_operation_v1` for binary protobuf or
`rm_jose_execute_owned_operation_json_v1` for ProtoJSON. Initialize the owner
slot to `NULL`. A successful transport call executes once and stores the
response owner in that slot; transport errors leave the slot unchanged.
The caller retains the request and may clear it after the call returns.

`rm_jose_owned_response_view_v1` returns an immutable pointer and encoded length.
Keep the owner alive until all reads finish, then release the original slot
through `rm_jose_owned_response_release_v1` in the same library image. Release
clears the slot, zeroizes the allocation, and frees it. Releasing an already
cleared slot succeeds. Synchronize reads and release; clear caller-owned copies
separately.

```c
#include "reallyme_jose.h"

rm_jose_status_t decode_response(const uint8_t *data, size_t len);

rm_jose_status_t execute_and_decode(const uint8_t *request, size_t request_len) {
    rm_jose_owned_response_t *owner = NULL;
    rm_jose_status_t status = rm_jose_execute_owned_operation_v1(
        RM_JOSE_ABI_VERSION, request, request_len, &owner);
    if (status != RM_JOSE_OK) {
        return status;
    }

    const uint8_t *data = NULL;
    size_t len = 0;
    status = rm_jose_owned_response_view_v1(
        RM_JOSE_ABI_VERSION, owner, &data, &len);
    if (status == RM_JOSE_OK) {
        status = decode_response(data, len);
    }
    rm_jose_status_t cleanup = rm_jose_owned_response_release_v1(
        RM_JOSE_ABI_VERSION, &owner);
    return cleanup == RM_JOSE_OK ? status : cleanup;
}
```

## Caller-owned buffers

`rm_jose_execute_operation_v1` and `rm_jose_execute_operation_json_v1` take
caller-owned input, output, and produced-length storage. Nonempty ranges must
fit live allocations and be mutually disjoint. Output and produced-length
storage may start uninitialized. A capacity mismatch returns the required
response size and leaves the output unchanged. Success writes the response
prefix and preserves the remaining output bytes.

Sizing and writing each execute the operation. Results can change between
calls, and the write reports its actual length. Prefer owned responses when
an operation must execute once. For caller-owned buffer cleanup, use
`rm_jose_zeroize_buffer` before releasing storage containing keys, claims,
compact tokens, JWK JSON, or plaintext.

C status values describe transport failures. Callers must not infer
semantic errors from the C status alone; decode `JoseOperationResponse` and
handle its operation outcome.

Build native artifacts with `cargo build -p reallyme-jose-ffi --profile release-ffi`.
`panic=abort` is unsupported. Custom dynamic builds that share a Rust standard
library across images are unsupported; do not unload such an image while
other components may retain its runtime state.

## License

Licensed under either the [MIT License](../../LICENSE-MIT) or the
[Apache License, Version 2.0](../../LICENSE-APACHE), at your option. See
[NOTICE](../../NOTICE).
