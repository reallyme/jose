/*
 * SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "reallyme_jose.h"

_Static_assert(RM_JOSE_ABI_VERSION == 1, "unexpected JOSE ABI version");
_Static_assert(RM_JOSE_OK == 0, "success status must remain zero");
_Static_assert(RM_JOSE_UNSUPPORTED_ABI == -6, "status values must remain stable");

int reallyme_jose_header_smoke(void) {
  uint32_t (*version)(void) = rm_jose_abi_version;
  rm_jose_status_t (*execute)(uint32_t, const uint8_t *, size_t, uint8_t *,
                              size_t, size_t *) = rm_jose_execute_operation_v1;
  return version != NULL && execute != NULL ? 0 : 1;
}
