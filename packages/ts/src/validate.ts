// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeJoseError } from "./errors.js";

export const MAX_JOSE_BINARY_REQUEST_BYTES = 1_048_576;
export const MAX_JOSE_JSON_REQUEST_BYTES = 1_572_864;
export const MAX_JOSE_RESPONSE_BYTES = 1_048_608;

export const invalidInput = (): never => {
  throw new ReallyMeJoseError("invalid-input");
};

export const ensureBytes = (value: Uint8Array): void => {
  if (!(value instanceof Uint8Array)) {
    invalidInput();
  }
};

export const ensureString = (value: string): void => {
  if (typeof value !== "string") {
    invalidInput();
  }
};

export const ensureBoolean = (value: boolean): void => {
  if (typeof value !== "boolean") {
    invalidInput();
  }
};

export const ensureUint64 = (value: bigint): void => {
  if (typeof value !== "bigint" || value < 0n || value > 18_446_744_073_709_551_615n) {
    invalidInput();
  }
};

export const utf8Length = (value: string): number => {
  ensureString(value);
  let length = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    let width = 0;
    if (codeUnit <= 0x7f) {
      width = 1;
    } else if (codeUnit <= 0x7ff) {
      width = 2;
    } else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const nextIndex = index + 1;
      if (nextIndex >= value.length) invalidInput();
      const next = value.charCodeAt(nextIndex);
      if (next < 0xdc00 || next > 0xdfff) invalidInput();
      index = nextIndex;
      width = 4;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      invalidInput();
    } else {
      width = 3;
    }
    if (length > Number.MAX_SAFE_INTEGER - width) invalidInput();
    length += width;
  }
  return length;
};

export const ensureAggregateLength = (...lengths: ReadonlyArray<number>): number => {
  let aggregate = 0;
  for (const length of lengths) {
    if (!Number.isSafeInteger(length) || length < 0) invalidInput();
    if (aggregate > MAX_JOSE_BINARY_REQUEST_BYTES - length) invalidInput();
    aggregate += length;
  }
  return aggregate;
};

export const ensureIndependentBytes = (
  value: Uint8Array,
  inputs: ReadonlyArray<Uint8Array>,
): void => {
  if (inputs.some((input) => input.buffer === value.buffer)) {
    throw new ReallyMeJoseError("provider-failure");
  }
};
