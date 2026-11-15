/*
 * SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#ifndef REALLYME_JOSE_H
#define REALLYME_JOSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RM_JOSE_ABI_VERSION UINT32_C(1)

typedef int32_t rm_jose_status_t;

enum {
  RM_JOSE_OK = 0,
  RM_JOSE_CALLER_ERROR = -1,
  RM_JOSE_PROVIDER_ERROR = -2,
  RM_JOSE_BACKEND_ERROR = -3,
  RM_JOSE_PANIC_CAUGHT = -4,
  RM_JOSE_OUTPUT_CAPACITY_MISMATCH = -5,
  RM_JOSE_UNSUPPORTED_ABI = -6
};

uint32_t rm_jose_abi_version(void);
size_t rm_jose_max_request_bytes(void);
size_t rm_jose_max_json_request_bytes(void);
size_t rm_jose_max_response_bytes(void);

/*
 * All nonempty ranges must identify one live allocation. Input must contain
 * initialized bytes and remain immutable for the call. Input, output, and
 * aligned produced-length storage must be mutually disjoint. Output and
 * produced-length storage must be exclusively writable and may start
 * uninitialized. A null byte pointer is permitted for an empty range.
 * Invalid pointer, length, or alias metadata returns RM_JOSE_CALLER_ERROR
 * without accessing any caller storage. After validation, *len_out is
 * initialized to zero. On capacity mismatch, *len_out is the exact required
 * size and output is unchanged. On success, only the first *len_out bytes
 * of output are written. Operation failures are encoded in the canonical
 * response and return RM_JOSE_OK at the C transport layer.
 * Callers may perform a zero-capacity sizing call followed by an independent
 * write call. Two successful JWE encryptions of the same request have equal
 * encoded response lengths. The write call reports its actual response size
 * if an independent operation outcome changes.
 */
rm_jose_status_t rm_jose_execute_operation_v1(
    uint32_t abi_version,
    const uint8_t *request_ptr,
    size_t request_len,
    uint8_t *output_ptr,
    size_t output_capacity,
    size_t *len_out);

rm_jose_status_t rm_jose_execute_operation_json_v1(
    uint32_t abi_version,
    const uint8_t *request_ptr,
    size_t request_len,
    uint8_t *output_ptr,
    size_t output_capacity,
    size_t *len_out);

/*
 * Single-execution ABI. Initialize *owner_out to NULL before execution.
 * The request must remain immutable and disjoint from that owner slot.
 * On success, the slot receives the unique owner of one canonical response,
 * including an operation error envelope when appropriate. On transport
 * failure the slot is unchanged. Release an existing owner before reuse.
 *
 * Keep the owner and all borrowed pointers in the same library image.
 * A view lends immutable response bytes until release. Its output slots
 * must be live, writable, and disjoint from each other and the allocation.
 * On error, both view outputs are unchanged.
 *
 * End all reads before releasing and synchronize accesses across threads.
 * Pass the unique owner slot to release. It becomes NULL before the
 * library wipes the response allocation and frees it. Releasing the
 * same cleared slot succeeds. Copies of the owner pointer are borrowed
 * aliases. Only release the owner through the original slot.
 */
typedef struct rm_jose_owned_response rm_jose_owned_response_t;

rm_jose_status_t rm_jose_execute_owned_operation_v1(
    uint32_t abi_version,
    const uint8_t *request,
    size_t request_len,
    rm_jose_owned_response_t **owner_out);

rm_jose_status_t rm_jose_execute_owned_operation_json_v1(
    uint32_t abi_version,
    const uint8_t *request,
    size_t request_len,
    rm_jose_owned_response_t **owner_out);

rm_jose_status_t rm_jose_owned_response_view_v1(
    uint32_t abi_version,
    const rm_jose_owned_response_t *owner,
    const uint8_t **data_out,
    size_t *len_out);

rm_jose_status_t rm_jose_owned_response_release_v1(
    uint32_t abi_version,
    rm_jose_owned_response_t **owner_slot);

/*
 * Wipes caller-owned mutable storage, which may start uninitialized.
 * The caller retains ownership. A null pointer is permitted for zero length.
 */
rm_jose_status_t rm_jose_zeroize_buffer(
    uint32_t abi_version,
    uint8_t *ptr,
    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* REALLYME_JOSE_H */
