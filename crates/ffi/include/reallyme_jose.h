/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
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
 * All nonempty ranges must identify one live allocation. Input, output, and
 * produced-length storage must be mutually disjoint. The output range must be
 * exclusively writable. On capacity mismatch, *len_out is the exact required
 * size and output is unchanged. On every other validated failure, *len_out is
 * zero after pointer and alias validation succeeds. Invalid pointer or alias
 * arguments are rejected without dereference or mutation. Operation failures
 * are encoded in the canonical response and return RM_JOSE_OK at the C
 * transport layer. Callers may perform a zero-capacity sizing call followed by
 * an independent write call; the encoded response length for the same request
 * is guaranteed to remain equal across those calls even when response bytes
 * contain fresh randomness.
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

/* Wipes caller-owned mutable storage; it does not free caller memory. */
rm_jose_status_t rm_jose_zeroize_buffer(
    uint32_t abi_version,
    uint8_t *ptr,
    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* REALLYME_JOSE_H */
