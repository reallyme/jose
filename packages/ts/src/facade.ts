// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { executeOperation } from "./boundary.js";
import { ReallyMeJoseError } from "./errors.js";
import type { ReallyMeJoseErrorBranch } from "./errors.js";
import {
  JoseErrorReason,
  JoseJweContentEncryptionAlgorithm,
  JoseJweKeyManagementAlgorithm,
  JoseOperationContractVersion,
  JoseOperationRequestSchema,
  JoseOperationResponseSchema,
  JoseSignatureAlgorithm,
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
import {
  ensureAggregateLength,
  ensureBoolean,
  ensureBytes,
  ensureString,
  ensureUint64,
  invalidInput,
  utf8Length,
} from "./validate.js";

export type ReallyMeJoseJwtHeaderPolicy = Readonly<{
  allowMissingType?: boolean;
  allowEmbeddedKeyHeaders?: boolean;
  acceptedTypes?: ReadonlyArray<string>;
}>;

export type ReallyMeJoseJwtTemporalPolicy = Readonly<{
  requireExpiration?: boolean;
  requireNotBefore?: boolean;
  requireIssuedAt?: boolean;
  clockSkewSeconds?: bigint;
  maximumFutureIssuedAtSkewSeconds?: bigint;
  verificationTimeUnixSeconds: bigint;
  expectedAudience: string;
  expectedIssuer?: string;
  expectedSubject?: string;
}>;

export type ReallyMeJoseJweHeaderPolicy = Readonly<{
  requireKeyIdentifier?: boolean;
  expectedKeyIdentifier?: string;
  expectedType?: string;
  expectedContentType?: string;
  expectedAgreementPartyUInfo?: Uint8Array;
  expectedAgreementPartyVInfo?: Uint8Array;
}>;

export type ReallyMeJoseSignJwsOptions = Readonly<{
  algorithm: JoseSignatureAlgorithm;
  privateKey: Uint8Array;
  payload: Uint8Array;
}>;

export type ReallyMeJoseVerifyJwsOptions = Readonly<{
  algorithm: JoseSignatureAlgorithm;
  compact: string;
  publicKey: Uint8Array;
}>;

export type ReallyMeJoseSignJwtOptions = Readonly<{
  claimsJson: Uint8Array;
  jwkJson: Uint8Array;
  privateKey: Uint8Array;
  type?: string;
}>;

export type ReallyMeJoseVerifyJwtOptions = Readonly<{
  compact: string;
  jwkJson: Uint8Array;
  publicKey: Uint8Array;
  headerPolicy?: ReallyMeJoseJwtHeaderPolicy;
  temporalPolicy?: ReallyMeJoseJwtTemporalPolicy;
  signatureOnly?: boolean;
}>;

export type ReallyMeJoseEncryptJweOptions = Readonly<{
  keyManagementAlgorithm: JoseJweKeyManagementAlgorithm;
  contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm;
  key: Uint8Array;
  plaintext: Uint8Array;
  keyIdentifier?: string;
  agreementPartyUInfo?: Uint8Array;
  agreementPartyVInfo?: Uint8Array;
  type?: string;
  contentType?: string;
}>;

export type ReallyMeJoseDecryptJweOptions = Readonly<{
  compact: string;
  keyManagementAlgorithm: JoseJweKeyManagementAlgorithm;
  contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm;
  key: Uint8Array;
  headerPolicy?: ReallyMeJoseJweHeaderPolicy;
}>;

const MAX_JWT_ACCEPTED_TYPE_VALUES = 32;
const PROTOBUF_REPEATED_STRING_OVERHEAD_BYTES = 5;

const malformedProviderResponse = (): never => {
  throw new ReallyMeJoseError("malformed-provider-response");
};

const ownedBytes = (value: Uint8Array): Uint8Array => {
  ensureBytes(value);
  return value.slice();
};

const optionalString = (value: string | undefined): string => {
  if (value === undefined) return "";
  ensureString(value);
  return value;
};

const optionalBoolean = (value: boolean | undefined, fallback: boolean): boolean => {
  if (value === undefined) return fallback;
  ensureBoolean(value);
  return value;
};

const optionalUint64 = (value: bigint | undefined): bigint => {
  if (value === undefined) return 0n;
  ensureUint64(value);
  return value;
};

const validateAlgorithm = (value: number, allowed: ReadonlyArray<number>): void => {
  if (!allowed.includes(value)) invalidInput();
};

const throwJoseError = (error: JoseError): never => {
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

const withResponse = <T>(
  request: JoseOperationRequest,
  consume: (response: JoseOperationResponse) => T,
): T => {
  const requestBytes = toBinary(JoseOperationRequestSchema, request);
  let responseBytes: Uint8Array | undefined;
  try {
    responseBytes = executeOperation(requestBytes);
    const response = decodeResponse(responseBytes);
    if (response.contractVersion !== JoseOperationContractVersion.V1) {
      malformedProviderResponse();
    }
    if (response.response.case === undefined) malformedProviderResponse();
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

const compactOutcome = (outcome: CompactOutcome): string => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case === "result") {
    ensureString(outcome.value.compact);
    if (outcome.value.compact.length === 0) return malformedProviderResponse();
    return outcome.value.compact;
  }
  return malformedProviderResponse();
};

const claimsOutcome = (outcome: JoseJwtDecodeUnsignedResponse["outcome"]): Uint8Array => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case === "result") return outcome.value.claimsJson.slice();
  return malformedProviderResponse();
};

const verifyOutcome = (outcome: JoseJwsVerifyResponse["outcome"]): void => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case !== "result") return malformedProviderResponse();
};

const plaintextOutcome = (outcome: JoseJweDecryptResponse["outcome"]): Uint8Array => {
  if (outcome.case === "error") return throwJoseError(outcome.value);
  if (outcome.case === "result") return outcome.value.plaintext.slice();
  return malformedProviderResponse();
};

const jwtHeaderPolicy = (policy: ReallyMeJoseJwtHeaderPolicy | undefined) => {
  if (policy === undefined) return undefined;
  if (
    policy.acceptedTypes !== undefined &&
    policy.acceptedTypes.length > MAX_JWT_ACCEPTED_TYPE_VALUES
  ) {
    invalidInput();
  }
  const acceptedTypes = policy.acceptedTypes === undefined ? [] : [...policy.acceptedTypes];
  for (const value of acceptedTypes) ensureString(value);
  return {
    allowMissingTyp: optionalBoolean(policy.allowMissingType, false),
    allowEmbeddedKeyHeader: optionalBoolean(policy.allowEmbeddedKeyHeaders, false),
    acceptedTypValues: acceptedTypes,
  };
};

const jwtHeaderPolicyLength = (
  policy: ReturnType<typeof jwtHeaderPolicy>,
): number => {
  if (policy === undefined) return 0;
  const lengths = policy.acceptedTypValues.flatMap(
    (value) => [utf8Length(value), PROTOBUF_REPEATED_STRING_OVERHEAD_BYTES],
  );
  return ensureAggregateLength(...lengths);
};

const jwtTemporalPolicyLength = (
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

const jwtTemporalPolicy = (policy: ReallyMeJoseJwtTemporalPolicy | undefined) => {
  if (policy === undefined) return undefined;
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

const jweHeaderPolicy = (
  policy: ReallyMeJoseJweHeaderPolicy | undefined,
  ownedApu: Uint8Array | undefined,
  ownedApv: Uint8Array | undefined,
) => {
  if (policy === undefined) return undefined;
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

export const ReallyMeJose = Object.freeze({
  signJws(options: ReallyMeJoseSignJwsOptions): string {
    validateAlgorithm(options.algorithm, [JoseSignatureAlgorithm.EDDSA, JoseSignatureAlgorithm.ES256]);
    const privateKey = ownedBytes(options.privateKey);
    const payload = ownedBytes(options.payload);
    try {
      ensureAggregateLength(privateKey.length, payload.length);
      const request = create(JoseOperationRequestSchema, {
        operation: { case: "jwsSign", value: { algorithm: options.algorithm, privateKey, payload } },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwsSign") return compactOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      privateKey.fill(0);
      payload.fill(0);
    }
  },

  verifyJws(options: ReallyMeJoseVerifyJwsOptions): void {
    validateAlgorithm(options.algorithm, [JoseSignatureAlgorithm.EDDSA, JoseSignatureAlgorithm.ES256]);
    ensureString(options.compact);
    const publicKey = ownedBytes(options.publicKey);
    try {
      ensureAggregateLength(utf8Length(options.compact), publicKey.length);
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jwsVerify",
          value: { algorithm: options.algorithm, compact: options.compact, publicKey },
        },
      });
      withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwsVerify") return verifyOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      publicKey.fill(0);
    }
  },

  encodeUnsignedJwt(claimsJson: Uint8Array): string {
    const claims = ownedBytes(claimsJson);
    try {
      ensureAggregateLength(claims.length);
      const request = create(JoseOperationRequestSchema, {
        operation: { case: "jwtEncodeUnsigned", value: { claimsJson: claims } },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwtEncodeUnsigned") {
          return compactOutcome(operation.value.outcome);
        }
        return malformedProviderResponse();
      });
    } finally {
      claims.fill(0);
    }
  },

  decodeUnsignedJwt(compact: string): Uint8Array {
    ensureString(compact);
    ensureAggregateLength(utf8Length(compact));
    const request = create(JoseOperationRequestSchema, {
      operation: { case: "jwtDecodeUnsigned", value: { compact } },
    });
    return withResponse(request, (response) => {
      const operation = response.response;
      if (operation.case === "jwtDecodeUnsigned") return claimsOutcome(operation.value.outcome);
      return malformedProviderResponse();
    });
  },

  signJwt(options: ReallyMeJoseSignJwtOptions): string {
    const claims = ownedBytes(options.claimsJson);
    const jwk = ownedBytes(options.jwkJson);
    const privateKey = ownedBytes(options.privateKey);
    const type = optionalString(options.type);
    try {
      ensureAggregateLength(claims.length, jwk.length, privateKey.length, utf8Length(type));
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jwtSign",
          value: { claimsJson: claims, jwkJson: jwk, privateKey, typ: type },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwtSign") return compactOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      claims.fill(0);
      jwk.fill(0);
      privateKey.fill(0);
    }
  },

  verifyJwt(options: ReallyMeJoseVerifyJwtOptions): Uint8Array {
    ensureString(options.compact);
    const jwk = ownedBytes(options.jwkJson);
    const publicKey = ownedBytes(options.publicKey);
    try {
      const headerPolicy = jwtHeaderPolicy(options.headerPolicy);
      const temporalPolicy = jwtTemporalPolicy(options.temporalPolicy);
      ensureAggregateLength(
        utf8Length(options.compact),
        jwk.length,
        publicKey.length,
        jwtHeaderPolicyLength(headerPolicy),
        jwtTemporalPolicyLength(temporalPolicy),
      );
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jwtVerify",
          value: {
            compact: options.compact,
            jwkJson: jwk,
            publicKey,
            headerPolicy,
            temporalPolicy,
            signatureOnly: optionalBoolean(options.signatureOnly, false),
          },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwtVerify") return claimsOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      jwk.fill(0);
      publicKey.fill(0);
    }
  },

  encryptJwe(options: ReallyMeJoseEncryptJweOptions): string {
    validateAlgorithm(options.keyManagementAlgorithm, [
      JoseJweKeyManagementAlgorithm.DIRECT,
      JoseJweKeyManagementAlgorithm.ECDH_ES_P256,
      JoseJweKeyManagementAlgorithm.ECDH_ES_P384,
      JoseJweKeyManagementAlgorithm.ECDH_ES_P521,
    ]);
    validateAlgorithm(options.contentEncryptionAlgorithm, [
      JoseJweContentEncryptionAlgorithm.A128GCM,
      JoseJweContentEncryptionAlgorithm.A192GCM,
      JoseJweContentEncryptionAlgorithm.A256GCM,
    ]);
    const key = ownedBytes(options.key);
    const plaintext = ownedBytes(options.plaintext);
    const apu = ownedBytes(options.agreementPartyUInfo ?? new Uint8Array());
    const apv = ownedBytes(options.agreementPartyVInfo ?? new Uint8Array());
    const keyIdentifier = optionalString(options.keyIdentifier);
    const type = optionalString(options.type);
    const contentType = optionalString(options.contentType);
    try {
      ensureAggregateLength(
        key.length,
        plaintext.length,
        apu.length,
        apv.length,
        utf8Length(keyIdentifier),
        utf8Length(type),
        utf8Length(contentType),
      );
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jweEncrypt",
          value: {
            keyManagementAlgorithm: options.keyManagementAlgorithm,
            contentEncryptionAlgorithm: options.contentEncryptionAlgorithm,
            key,
            plaintext,
            kid: keyIdentifier,
            apu,
            apv,
            typ: type,
            cty: contentType,
          },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jweEncrypt") return compactOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      key.fill(0);
      plaintext.fill(0);
      apu.fill(0);
      apv.fill(0);
    }
  },

  decryptJwe(options: ReallyMeJoseDecryptJweOptions): Uint8Array {
    ensureString(options.compact);
    validateAlgorithm(options.keyManagementAlgorithm, [
      JoseJweKeyManagementAlgorithm.DIRECT,
      JoseJweKeyManagementAlgorithm.ECDH_ES_P256,
      JoseJweKeyManagementAlgorithm.ECDH_ES_P384,
      JoseJweKeyManagementAlgorithm.ECDH_ES_P521,
    ]);
    validateAlgorithm(options.contentEncryptionAlgorithm, [
      JoseJweContentEncryptionAlgorithm.A128GCM,
      JoseJweContentEncryptionAlgorithm.A192GCM,
      JoseJweContentEncryptionAlgorithm.A256GCM,
    ]);
    const key = ownedBytes(options.key);
    const expectedApu = options.headerPolicy?.expectedAgreementPartyUInfo === undefined
      ? undefined
      : ownedBytes(options.headerPolicy.expectedAgreementPartyUInfo);
    const expectedApv = options.headerPolicy?.expectedAgreementPartyVInfo === undefined
      ? undefined
      : ownedBytes(options.headerPolicy.expectedAgreementPartyVInfo);
    try {
      ensureAggregateLength(
        utf8Length(options.compact),
        key.length,
        expectedApu?.length ?? 0,
        expectedApv?.length ?? 0,
        options.headerPolicy?.expectedKeyIdentifier === undefined
          ? 0
          : utf8Length(options.headerPolicy.expectedKeyIdentifier),
        options.headerPolicy?.expectedType === undefined
          ? 0
          : utf8Length(options.headerPolicy.expectedType),
        options.headerPolicy?.expectedContentType === undefined
          ? 0
          : utf8Length(options.headerPolicy.expectedContentType),
      );
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jweDecrypt",
          value: {
            compact: options.compact,
            keyManagementAlgorithm: options.keyManagementAlgorithm,
            contentEncryptionAlgorithm: options.contentEncryptionAlgorithm,
            key,
            headerPolicy: jweHeaderPolicy(options.headerPolicy, expectedApu, expectedApv),
          },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jweDecrypt") return plaintextOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      key.fill(0);
      expectedApu?.fill(0);
      expectedApv?.fill(0);
    }
  },
});
