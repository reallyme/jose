// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type { Message } from "@bufbuild/protobuf";
import { executeOperation } from "./boundary.js";
import { ReallyMeJoseError, ReallyMeJoseSdkErrorCode } from "./errors.js";
import type { ReallyMeJoseErrorBranch } from "./errors.js";
import {
  JoseErrorReason,
  JoseJweCompressionAlgorithm,
  JoseJwtHeaderEncodeOptionsSchema,
  JoseJwtVerificationPolicySchema,
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
  ReallyMeJoseJwtHeaderOptions,
  ReallyMeJoseJwtClaimsPolicy,
} from "./facade.js";
import {
  ensureAggregateLength,
  ensureBoolean,
  ensureBytes,
  ensureObjectFields,
  ensureString,
  ensureUint64,
  invalidInput,
  resourceLimit,
  MAX_JOSE_BINARY_REQUEST_BYTES,
  utf8Length,
} from "./validate.js";
import {
  JWT_HEADER_OPTION_FIELDS, JWT_HEADER_POLICY_FIELDS, JWT_CLAIMS_POLICY_FIELDS,
  JWE_HEADER_POLICY_FIELDS,
} from "./facade-shapes.js";

import { ACCEPTED_TYPE_VALUES, STRICT_TEMPORAL_DEFAULTS, errorBranch } from "./proto/contract-values.js";
const MAX_JWT_ACCEPTED_TYPE_VALUES = ACCEPTED_TYPE_VALUES;
const PROTOBUF_REPEATED_STRING_OVERHEAD_BYTES = 5;

export const malformedProviderResponse = (): never => {
  throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.MALFORMED_PROVIDER_RESPONSE);
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

export const optionalHeaderString = (value: string | undefined): string | undefined => {
  if (value !== undefined) ensureString(value);
  return value;
};

export const jwtHeaderOptions = (options: ReallyMeJoseJwtHeaderOptions | undefined) => {
  if (options === undefined) return undefined;
  ensureObjectFields(options, JWT_HEADER_OPTION_FIELDS);
  const typ = optionalHeaderString(options.type);
  if (typ === "") {
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.JOSE_FAILURE, "primitive", JoseErrorReason.JWT_INVALID_HEADER);
  }
  return create(JoseJwtHeaderEncodeOptionsSchema, { typ });
};

export const jwtVerification = (value: import("./contract-verification.js").ReallyMeJoseJwtVerification) => {
  // Validate the discriminated view before reading its policy. The generated
  // mode vocabulary is exactly the schema oneof, including temporal-only.
  ensureObjectFields(value, { mode: true, policy: true });
  if (value.mode === "signatureOnly") {
    ensureObjectFields(value, { mode: true });
    return create(JoseJwtVerificationPolicySchema, { mode: { case: "signatureOnly", value: {} } });
  }
  if (value.mode === "claims") {
    const claims = jwtClaimsPolicy(value.policy);
    if (claims === undefined) return invalidInput();
    return create(JoseJwtVerificationPolicySchema, { mode: { case: "claims", value: claims } });
  }
  if (value.mode === "temporalOnly") {
    ensureObjectFields(value.policy, { requireExpiration: true, requireNotBefore: true, requireIssuedAt: true,
      clockSkewSeconds: true, maximumFutureIssuedAtSkewSeconds: true, verificationTimeUnixSeconds: true });
    ensureUint64(value.policy.verificationTimeUnixSeconds);
    if (value.policy.verificationTimeUnixSeconds === 0n) invalidInput();
    return create(JoseJwtVerificationPolicySchema, { mode: { case: "temporalOnly", value: {
      nowUnix: value.policy.verificationTimeUnixSeconds,
      options: {
        requireExp: optionalBoolean(value.policy.requireExpiration, STRICT_TEMPORAL_DEFAULTS.requireExp),
        requireNbf: optionalBoolean(value.policy.requireNotBefore, STRICT_TEMPORAL_DEFAULTS.requireNbf),
        requireIat: optionalBoolean(value.policy.requireIssuedAt, STRICT_TEMPORAL_DEFAULTS.requireIat),
        clockSkewSeconds: optionalUint64(value.policy.clockSkewSeconds, STRICT_TEMPORAL_DEFAULTS.clockSkewSeconds),
        maxFutureIatSkewSeconds: optionalUint64(value.policy.maximumFutureIssuedAtSkewSeconds, STRICT_TEMPORAL_DEFAULTS.maxFutureIatSkewSeconds),
      },
    } } });
  }
  return invalidInput();
};

export const optionalBoolean = (value: boolean | undefined, fallback: boolean): boolean => {
  if (value === undefined) return fallback;
  ensureBoolean(value);
  return value;
};

const optionalUint64 = (value: bigint | undefined, fallback: bigint): bigint => {
  if (value === undefined) return fallback;
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
  ): never => {
    if (
      errorBranch(reason) !== publicBranch
    ) {
      malformedProviderResponse();
    }
    throw new ReallyMeJoseError(ReallyMeJoseSdkErrorCode.JOSE_FAILURE, publicBranch, reason);
  };
  switch (branch) {
    case "primitive":
      return failWithReason("primitive", error.error.value.reason);
    case "provider":
      return failWithReason("provider", error.error.value.reason);
    case "backend":
      return failWithReason("backend", error.error.value.reason);
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
    if (response.contractVersion !== JoseOperationContractVersion.V2) {
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
  try {
    requireClean(outcome.value);
  } finally {
    // The compatibility facade returns only verification status. Do not leave
    // authenticated identity or payload bytes in managed response buffers.
    outcome.value.protectedHeaderJson.fill(0);
    outcome.value.payload.fill(0);
  }
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
  ensureObjectFields(policy, JWT_HEADER_POLICY_FIELDS);
  if (policy.acceptedTypes !== undefined && !Array.isArray(policy.acceptedTypes)) invalidInput();
  if (
    policy.acceptedTypes !== undefined &&
    policy.acceptedTypes.length > MAX_JWT_ACCEPTED_TYPE_VALUES
  ) {
    resourceLimit();
  }
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

const expectedClaimConstraint = (value: string | undefined): { value: string } | undefined => {
  if (value === undefined) return undefined;
  ensureString(value);
  if (value.length === 0) {
    throw new ReallyMeJoseError(
      ReallyMeJoseSdkErrorCode.JOSE_FAILURE,
      "primitive",
      JoseErrorReason.JWT_INVALID_VERIFICATION_POLICY,
    );
  }
  return { value };
};

export const jwtClaimsPolicy = (policy: ReallyMeJoseJwtClaimsPolicy | undefined) => {
  if (policy === undefined) return undefined;
  ensureObjectFields(policy, JWT_CLAIMS_POLICY_FIELDS);
  ensureUint64(policy.verificationTimeUnixSeconds);
  if (policy.verificationTimeUnixSeconds === 0n) invalidInput();
  ensureString(policy.expectedAudience);
  if (policy.expectedAudience.length === 0) invalidInput();
  return {
    requireExp: optionalBoolean(policy.requireExpiration, STRICT_TEMPORAL_DEFAULTS.requireExp),
    requireNbf: optionalBoolean(policy.requireNotBefore, STRICT_TEMPORAL_DEFAULTS.requireNbf),
    requireIat: optionalBoolean(policy.requireIssuedAt, STRICT_TEMPORAL_DEFAULTS.requireIat),
    clockSkewSeconds: optionalUint64(policy.clockSkewSeconds, STRICT_TEMPORAL_DEFAULTS.clockSkewSeconds),
    maxFutureIatSkewSeconds: optionalUint64(policy.maximumFutureIssuedAtSkewSeconds, STRICT_TEMPORAL_DEFAULTS.maxFutureIatSkewSeconds),
    nowUnix: policy.verificationTimeUnixSeconds,
    expectedAudience: policy.expectedAudience,
    expectedIssuerConstraint: expectedClaimConstraint(policy.expectedIssuer),
    expectedSubjectConstraint: expectedClaimConstraint(policy.expectedSubject),
  };
};

export const jweHeaderPolicy = (
  policy: ReallyMeJoseJweHeaderPolicy | undefined,
  ownedApu: Uint8Array | undefined,
  ownedApv: Uint8Array | undefined,
) => {
  if (policy === undefined) return undefined;
  ensureObjectFields(policy, JWE_HEADER_POLICY_FIELDS);
  const configuredCompressionAlgorithms = policy.allowedCompressionAlgorithms === undefined ? [] : policy.allowedCompressionAlgorithms;
  if (!Array.isArray(configuredCompressionAlgorithms)) invalidInput();
  // Each packed enum needs at least one wire byte. Bound the list before
  // copying it so a sparse attacker-controlled array cannot exhaust the host.
  if (configuredCompressionAlgorithms.length > MAX_JOSE_BINARY_REQUEST_BYTES) resourceLimit();
  const allowedCompressionAlgorithms: JoseJweCompressionAlgorithm[] = [
    ...configuredCompressionAlgorithms,
  ];
  for (const algorithm of allowedCompressionAlgorithms) {
    validateAlgorithm(algorithm, [JoseJweCompressionAlgorithm.DEFLATE]);
  }
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
    allowedCompressionAlgorithms,
  };
};
