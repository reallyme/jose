# ReallyMe JOSE C ABI

`reallyme-jose-ffi` is the non-publishable native boundary used by supported
platform packages. It executes binary protobuf and ProtoJSON requests and returns the same
canonical binary response for either encoding. The C ABI also provides
authoritative size limits and caller-owned buffer cleanup.

Callers must invoke `rm_jose_abi_version` and require the exact expected value
before calling or casting any other loaded symbol. Operation calls also receive
the ABI version and fail closed if it differs.

## Owned responses

Use `rm_jose_execute_owned_operation_v1` for binary protobuf and
`rm_jose_execute_owned_operation_json_v1` for ProtoJSON. Initialize the
owner slot to `NULL`. Either function executes the request once and
stores a unique owner in that slot on transport success. Transport errors
leave the slot unchanged. The request remains caller-owned and may be
cleared as soon as the execute call returns.

`rm_jose_owned_response_view_v1` returns an immutable pointer and its exact
encoded length. Keep the owner alive while reading the view. End all reads,
then pass the original slot to `rm_jose_owned_response_release_v1` in the
same library image. Release clears the slot, zeroizes the response
allocation including spare capacity, and frees it. Releasing the cleared
slot succeeds. Synchronize release with all use of the owner and its views.
Caller-owned copies have their own cleanup obligation.

```c
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

JNI and Swift's runtime-loaded provider use the owned calls when paired
with a native image exporting them. Swift packages linked to an older
XCFramework continue to use the caller-owned buffer calls.

## Caller-owned buffers

The existing `rm_jose_execute_operation_v1` and
`rm_jose_execute_operation_json_v1` take caller-owned input, output, and
produced-length storage. Nonempty ranges must fit within live allocations
and be mutually disjoint. Output and produced-length storage may start
uninitialized. A capacity mismatch reports the exact required response size
and leaves the output unchanged. A successful call writes the encoded
response into the reported prefix and preserves the remaining bytes.
A sizing call and a write call each execute the request. If the operation
outcome changes between calls, the write call reports its actual length.

Call `rm_jose_zeroize_buffer` before releasing caller-owned storage that
may contain private keys, claims, compact tokens, JWK JSON, or plaintext.

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

Licensed under either the [MIT License](../../LICENSE-MIT) or the
[Apache License, Version 2.0](../../LICENSE-APACHE), at your option. See
[NOTICE](../../NOTICE).
