/*
 * SPDX-FileCopyrightText: 2026 ReallyMe LLC
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#include "reallyme_jose.h"

_Static_assert(RM_JOSE_ABI_VERSION == 1, "unexpected JOSE ABI version");
_Static_assert(RM_JOSE_OK == 0, "success status must remain zero");
_Static_assert(RM_JOSE_UNSUPPORTED_ABI == -6, "status values must remain stable");

int reallyme_jose_header_smoke(void) {
  uint32_t (*version)(void) = rm_jose_abi_version;
  size_t (*max_request)(void) = rm_jose_max_request_bytes;
  size_t (*max_json_request)(void) = rm_jose_max_json_request_bytes;
  size_t (*max_response)(void) = rm_jose_max_response_bytes;
  rm_jose_status_t (*execute_binary)(uint32_t, const uint8_t *, size_t,
                                     uint8_t *, size_t, size_t *) =
      rm_jose_execute_operation_v1;
  rm_jose_status_t (*execute_json)(uint32_t, const uint8_t *, size_t,
                                   uint8_t *, size_t, size_t *) =
      rm_jose_execute_operation_json_v1;
  rm_jose_status_t (*zeroize)(uint32_t, uint8_t *, size_t) =
      rm_jose_zeroize_buffer;
  return version != NULL && max_request != NULL && max_json_request != NULL &&
                 max_response != NULL && execute_binary != NULL &&
                 execute_json != NULL && zeroize != NULL
             ? 0
             : 1;
}
