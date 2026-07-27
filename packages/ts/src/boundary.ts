// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeJoseError } from "./errors.js";
import { requireReallyMeJoseWasmProvider } from "./provider.js";
import type { ReallyMeJoseWasmProvider } from "./provider.js";
import {
  ensureBytes,
  ensureIndependentBytes,
  MAX_JOSE_BINARY_REQUEST_BYTES,
  MAX_JOSE_JSON_REQUEST_BYTES,
  MAX_JOSE_RESPONSE_BYTES,
} from "./validate.js";

const execute = (
  provider: ReallyMeJoseWasmProvider,
  request: Uint8Array,
  maximum: number,
  json: boolean,
): Uint8Array => {
  ensureBytes(request);
  if (request.length > maximum) {
    throw new ReallyMeJoseError("invalid-input");
  }
  const result = json
    ? provider.executeOperationJson(request)
    : provider.executeOperation(request);
  if (!(result instanceof Uint8Array)) {
    throw new ReallyMeJoseError("provider-failure");
  }
  ensureIndependentBytes(result, [request]);
  if (result.length === 0 || result.length > MAX_JOSE_RESPONSE_BYTES) {
    result.fill(0);
    throw new ReallyMeJoseError("provider-failure");
  }
  return result;
};

export const executeOperation = (request: Uint8Array): Uint8Array =>
  execute(
    requireReallyMeJoseWasmProvider(),
    request,
    MAX_JOSE_BINARY_REQUEST_BYTES,
    false,
  );

export const executeOperationJson = (request: Uint8Array): Uint8Array =>
  execute(
    requireReallyMeJoseWasmProvider(),
    request,
    MAX_JOSE_JSON_REQUEST_BYTES,
    true,
  );
