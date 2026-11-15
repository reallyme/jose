// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ReallyMeJoseError, ReallyMeJoseSdkErrorCode } from "./errors.js";
import { JoseErrorReason } from "./proto/generated/reallyme/jose/v1/jose_pb.js";

import { COMPACT_BYTES, PROTO_JSON_BYTES, RESPONSE_OVERHEAD_BYTES } from "./proto/contract-values.js";

export const MAX_JOSE_BINARY_REQUEST_BYTES = COMPACT_BYTES;
export const MAX_JOSE_JSON_REQUEST_BYTES = PROTO_JSON_BYTES;
export const MAX_JOSE_RESPONSE_BYTES = COMPACT_BYTES + RESPONSE_OVERHEAD_BYTES;

export const invalidInput = (): never => {
  throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.INVALID_INPUT);
};

export const resourceLimit = (): never => {
  throw new ReallyMeJoseError(
    ReallyMeJoseSdkErrorCode.JOSE_FAILURE,
    "primitive",
    JoseErrorReason.COMMON_RESOURCE_LIMIT_EXCEEDED,
  );
};

export const ensureObjectFields = (value: unknown, allowed: Readonly<Record<string, true>>): void => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return invalidInput();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) invalidInput();
  for (const field of Object.keys(allowed)) {
    // Optional settings must be absent or owned by this record. A polluted
    // Object.prototype must never supply authorization or verification policy.
    if (!Object.hasOwn(value, field) && field in value) invalidInput();
  }
  for (const field of Reflect.ownKeys(value)) {
    if (typeof field !== "string" || !Object.hasOwn(allowed, field)) invalidInput();
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) invalidInput();
  }
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
    if (length > Number.MAX_SAFE_INTEGER - width) resourceLimit();
    length += width;
  }
  return length;
};

export const ensureAggregateLength = (...lengths: ReadonlyArray<number>): number => {
  let aggregate = 0;
  for (const length of lengths) {
    if (!Number.isSafeInteger(length) || length < 0) invalidInput();
    if (aggregate > MAX_JOSE_BINARY_REQUEST_BYTES - length) resourceLimit();
    aggregate += length;
  }
  return aggregate;
};

export const ensureIndependentBytes = (
  value: Uint8Array,
  inputs: ReadonlyArray<Uint8Array>,
): void => {
  if (inputs.some((input) => input.buffer === value.buffer)) {
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.PROVIDER_FAILURE);
  }
};
