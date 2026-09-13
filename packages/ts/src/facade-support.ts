// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//

import { fromBinary, toBinary } from "@bufbuild/protobuf";
import type { Message } from "@bufbuild/protobuf";
import { executeOperation } from "./boundary.js";
import { ReallyMeJoseError } from "./errors.js";
import type { ReallyMeJoseErrorBranch } from "./errors.js";
import {
  JoseErrorReason,
  JoseOperationContractVersion,
  JoseOperationRequestSchema,
  JoseOperationResponseSchema,
} from "./proto/generated/reallyme/jose/v1/jose_pb.js";
import type {
  JoseError,
  JoseJweDecryptResponse,
  JoseJwsSignResponse,
  JoseJwsVerifyResponse,
  JoseJwtDecodeUnsignedResponse,
  JoseOperationRequest,
  JoseOperationResponse,
} from "./proto/generated/reallyme/jose/v1/jose_pb.js";
import type {
  ReallyMeJoseJweHeaderPolicy,
  ReallyMeJoseJwtHeaderPolicy,
  ReallyMeJoseJwtTemporalPolicy,
} from "./facade.js";
import {
  ensureAggregateLength,
  ensureBoolean,
  ensureBytes,
  ensureObject,
  ensureString,
  ensureUint64,
  invalidInput,
  utf8Length,
} from "./validate.js";

const MAX_JWT_ACCEPTED_TYPE_VALUES = 32;
const PROTOBUF_REPEATED_STRING_OVERHEAD_BYTES = 5;

export const malformedProviderResponse = (): never => {
  throw new ReallyMeJoseError("malformed-provider-response");
};

const requireClean = (message: Message): void => {
  if (message.$unknown !== undefined && message.$unknown.length !== 0) {
    malformedProviderResponse();
  }
};

export const ownedBytes = (value: Uint8Array, owners: Uint8Array[]): Uint8Array => {
  ensureBytes(value);
  ensureAggregateLength(value.length);
  // Buffer.slice() aliases its input. Always construct a plain Uint8Array so
  // cleanup cannot erase caller storage, including Node.js Buffer inputs.
  const owned = new Uint8Array(value);
  owners.push(owned);
  return owned;
};

export const optionalString = (value: string | undefined): string => {
  if (value === undefined) return "";
  ensureString(value);
  return value;
};

export const optionalBoolean = (value: boolean | undefined, fallback: boolean): boolean => {
  if (value === undefined) return fallback;
  ensureBoolean(value);
  return value;
};

const optionalUint64 = (value: bigint | undefined): bigint => {
  if (value === undefined) return 0n;
  ensureUint64(value);
  return value;
};

export const validateAlgorithm = (value: number, allowed: ReadonlyArray<number>): void => {
  if (!allowed.includes(value)) invalidInput();
};

const throwJoseError = (error: JoseError): never => {
  requireClean(error);
  if (error.error.case !== undefined) requireClean(error.error.value);
  const branch = error.error.case;
  const failWithReason = (
    publicBranch: ReallyMeJoseErrorBranch,
    reason: JoseErrorReason,
    minimum: number,
    maximum: number,
  ): never => {
    if (
      reason === JoseErrorReason.UNSPECIFIED ||
      JoseErrorReason[reason] === undefined ||
      reason < minimum ||
      reason > maximum
    ) {
      malformedProviderResponse();
    }
    throw new ReallyMeJoseError("jose-failure", publicBranch, reason);
  };
  switch (branch) {
    case "primitive":
      return failWithReason("primitive", error.error.value.reason, 1, 799);
    case "provider":
      return failWithReason("provider", error.error.value.reason, 800, 802);
    case "backend":
      return failWithReason("backend", error.error.value.reason, 900, 902);
    default:
      return malformedProviderResponse();
  }
};

const decodeResponse = (responseBytes: Uint8Array): JoseOperationResponse => {
  try {
    return fromBinary(JoseOperationResponseSchema, responseBytes);
  } catch (_error: unknown) {
    return malformedProviderResponse();
  }
};

export const withResponse = <T>(
  request: JoseOperationRequest,
  consume: (response: JoseOperationResponse) => T,
): T => {
  const requestBytes = toBinary(JoseOperationRequestSchema, request);
  let responseBytes: Uint8Array | undefined;
  try {
    responseBytes = executeOperation(requestBytes);
    const response = decodeResponse(responseBytes);
    requireClean(response);
    if (response.contractVersion !== JoseOperationContractVersion.V1) {
      malformedProviderResponse();
    }
    if (response.response.case === undefined) return malformedProviderResponse();
    requireClean(response.response.value);
    if (response.response.case === "boundaryError") {
      throwJoseError(response.response.value);
    }
    return consume(response);
  } finally {
    requestBytes.fill(0);
    responseBytes?.fill(0);
  }
};

type CompactOutcome = JoseJwsSignResponse["outcome"];

export const compactOutcome = (outcome: CompactOutcome): string => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case === "result") {
    requireClean(outcome.value);
    ensureString(outcome.value.compact);
    if (outcome.value.compact.length === 0) return malformedProviderResponse();
    return outcome.value.compact;
  }
  return malformedProviderResponse();
};

export const claimsOutcome = (outcome: JoseJwtDecodeUnsignedResponse["outcome"]): Uint8Array => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case === "result") {
    requireClean(outcome.value);
    return new Uint8Array(outcome.value.claimsJson);
  }
  return malformedProviderResponse();
};

export const verifyOutcome = (outcome: JoseJwsVerifyResponse["outcome"]): void => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case !== "result") return malformedProviderResponse();
  requireClean(outcome.value);
};

export const plaintextOutcome = (outcome: JoseJweDecryptResponse["outcome"]): Uint8Array => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case === "result") {
    requireClean(outcome.value);
    return new Uint8Array(outcome.value.plaintext);
  }
  return malformedProviderResponse();
};

export const jwtHeaderPolicy = (policy: ReallyMeJoseJwtHeaderPolicy | undefined) => {
  if (policy === undefined) return undefined;
  ensureObject(policy);
  if (
    policy.acceptedTypes !== undefined &&
    policy.acceptedTypes.length > MAX_JWT_ACCEPTED_TYPE_VALUES
  ) {
    invalidInput();
  }
  if (policy.acceptedTypes !== undefined && !Array.isArray(policy.acceptedTypes)) invalidInput();
  const acceptedTypes = policy.acceptedTypes === undefined ? [] : [...policy.acceptedTypes];
  for (const value of acceptedTypes) ensureString(value);
  return {
    allowMissingTyp: optionalBoolean(policy.allowMissingType, false),
    allowEmbeddedKeyHeader: optionalBoolean(policy.allowEmbeddedKeyHeaders, false),
    acceptedTypValues: acceptedTypes,
  };
};

export const jwtHeaderPolicyLength = (
  policy: ReturnType<typeof jwtHeaderPolicy>,
): number => {
  if (policy === undefined) return 0;
  const lengths = policy.acceptedTypValues.flatMap(
    (value) => [utf8Length(value), PROTOBUF_REPEATED_STRING_OVERHEAD_BYTES],
  );
  return ensureAggregateLength(...lengths);
};

export const jwtTemporalPolicyLength = (
  policy: ReturnType<typeof jwtTemporalPolicy>,
): number => {
  if (policy === undefined) return 0;
  const lengths = [
    utf8Length(policy.expectedAudience),
    utf8Length(policy.expectedIssuer),
    utf8Length(policy.expectedSubject),
  ];
  return ensureAggregateLength(...lengths);
};

export const jwtTemporalPolicy = (policy: ReallyMeJoseJwtTemporalPolicy | undefined) => {
  if (policy === undefined) return undefined;
  ensureObject(policy);
  ensureUint64(policy.verificationTimeUnixSeconds);
  if (policy.verificationTimeUnixSeconds === 0n) invalidInput();
  ensureString(policy.expectedAudience);
  if (policy.expectedAudience.length === 0) invalidInput();
  return {
    requireExp: optionalBoolean(policy.requireExpiration, false),
    requireNbf: optionalBoolean(policy.requireNotBefore, false),
    requireIat: optionalBoolean(policy.requireIssuedAt, false),
    clockSkewSeconds: optionalUint64(policy.clockSkewSeconds),
    maxFutureIatSkewSeconds: optionalUint64(policy.maximumFutureIssuedAtSkewSeconds),
    nowUnix: policy.verificationTimeUnixSeconds,
    expectedAudience: policy.expectedAudience,
    expectedIssuer: optionalString(policy.expectedIssuer),
    expectedSubject: optionalString(policy.expectedSubject),
  };
};

export const jweHeaderPolicy = (
  policy: ReallyMeJoseJweHeaderPolicy | undefined,
  ownedApu: Uint8Array | undefined,
  ownedApv: Uint8Array | undefined,
) => {
  if (policy === undefined) return undefined;
  ensureObject(policy);
  return {
    requireKid: optionalBoolean(policy.requireKeyIdentifier, false),
    expectedKid: policy.expectedKeyIdentifier === undefined
      ? undefined
      : { value: optionalString(policy.expectedKeyIdentifier) },
    expectedTyp: policy.expectedType === undefined
      ? undefined
      : { value: optionalString(policy.expectedType) },
    expectedCty: policy.expectedContentType === undefined
      ? undefined
      : { value: optionalString(policy.expectedContentType) },
    expectedApu: ownedApu === undefined ? undefined : { value: ownedApu },
    expectedApv: ownedApv === undefined ? undefined : { value: ownedApv },
  };
};
