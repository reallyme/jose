// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { create } from "@bufbuild/protobuf";
import {
  JoseJweCompressionAlgorithm,
  JoseJweContentEncryptionAlgorithm,
  JoseJweKeyManagementAlgorithm,
  JoseOperationRequestSchema,
  JoseSignatureAlgorithm,
} from "./proto/generated/reallyme/jose/v1/jose_pb.js";
import {
  ensureAggregateLength,
  ensureObjectFields,
  ensureString,
  utf8Length,
} from "./validate.js";
import {
  SIGN_JWS_FIELDS, VERIFY_JWS_FIELDS, SIGN_JWT_FIELDS, VERIFY_JWT_FIELDS,
  ENCRYPT_JWE_FIELDS, DECRYPT_JWE_FIELDS, JWE_HEADER_POLICY_FIELDS,
} from "./facade-shapes.js";
import {
  claimsOutcome,
  compactOutcome,
  jweHeaderPolicy,
  jwtHeaderPolicy,
  jwtHeaderOptions,
  jwtHeaderPolicyLength,
  jwtVerification,
  malformedProviderResponse,
  optionalHeaderString,
  ownedBytes,
  plaintextOutcome,
  validateAlgorithm,
  verifyOutcome,
  withResponse,
} from "./facade-support.js";

export type ReallyMeJoseJwtHeaderPolicy = Readonly<{
  allowMissingType?: boolean;
  allowEmbeddedKeyHeaders?: boolean;
  acceptedTypes?: ReadonlyArray<string>;
}>;

export type ReallyMeJoseJwtClaimsPolicy = Readonly<{
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
  allowedCompressionAlgorithms?: ReadonlyArray<JoseJweCompressionAlgorithm>;
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
  headerOptions?: ReallyMeJoseJwtHeaderOptions;
}>;

export type ReallyMeJoseJwtHeaderOptions = Readonly<{
  type?: string;
}>;

export type ReallyMeJoseVerifyJwtOptions = Readonly<{
  compact: string;
  jwkJson: Uint8Array;
  publicKey: Uint8Array;
  headerPolicy?: ReallyMeJoseJwtHeaderPolicy;
  verification: import("./contract-verification.js").ReallyMeJoseJwtVerification;
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
  compressionAlgorithm?: JoseJweCompressionAlgorithm;
}>;

export type ReallyMeJoseDecryptJweOptions = Readonly<{
  compact: string;
  keyManagementAlgorithm: JoseJweKeyManagementAlgorithm;
  contentEncryptionAlgorithm: JoseJweContentEncryptionAlgorithm;
  key: Uint8Array;
  headerPolicy?: ReallyMeJoseJweHeaderPolicy;
}>;


export const ReallyMeJose = Object.freeze({
  signJws(options: ReallyMeJoseSignJwsOptions): string {
    ensureObjectFields(options, SIGN_JWS_FIELDS);
    validateAlgorithm(options.algorithm, [JoseSignatureAlgorithm.EDDSA, JoseSignatureAlgorithm.ES256, JoseSignatureAlgorithm.ES256K]);
    const owners: Uint8Array[] = [];
    try {
      const privateKey = ownedBytes(options.privateKey, owners);
      const payload = ownedBytes(options.payload, owners);
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
      for (const owned of owners) owned.fill(0);
    }
  },

  verifyJws(options: ReallyMeJoseVerifyJwsOptions): void {
    ensureObjectFields(options, VERIFY_JWS_FIELDS);
    validateAlgorithm(options.algorithm, [JoseSignatureAlgorithm.EDDSA, JoseSignatureAlgorithm.ES256, JoseSignatureAlgorithm.ES256K]);
    ensureString(options.compact);
    const owners: Uint8Array[] = [];
    try {
      const publicKey = ownedBytes(options.publicKey, owners);
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
      for (const owned of owners) owned.fill(0);
    }
  },

  encodeUnsignedJwt(claimsJson: Uint8Array): string {
    const owners: Uint8Array[] = [];
    try {
      const claims = ownedBytes(claimsJson, owners);
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
      for (const owned of owners) owned.fill(0);
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
    ensureObjectFields(options, SIGN_JWT_FIELDS);
    const owners: Uint8Array[] = [];
    try {
      const claims = ownedBytes(options.claimsJson, owners);
      const jwk = ownedBytes(options.jwkJson, owners);
      const privateKey = ownedBytes(options.privateKey, owners);
      const headerOptions = jwtHeaderOptions(options.headerOptions);
      ensureAggregateLength(claims.length, jwk.length, privateKey.length, utf8Length(headerOptions?.typ ?? ""));
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jwtSign",
          value: { claimsJson: claims, jwkJson: jwk, privateKey, headerOptions },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwtSign") return compactOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      for (const owned of owners) owned.fill(0);
    }
  },

  verifyJwt(options: ReallyMeJoseVerifyJwtOptions): Uint8Array {
    ensureObjectFields(options, VERIFY_JWT_FIELDS);
    ensureString(options.compact);
    const owners: Uint8Array[] = [];
    try {
      const jwk = ownedBytes(options.jwkJson, owners);
      const publicKey = ownedBytes(options.publicKey, owners);
      const headerPolicy = jwtHeaderPolicy(options.headerPolicy);
      const verification = jwtVerification(options.verification);
      ensureAggregateLength(
        utf8Length(options.compact),
        jwk.length,
        publicKey.length,
        jwtHeaderPolicyLength(headerPolicy),
        verification.mode.case === "claims" ? utf8Length(verification.mode.value.expectedAudience) +
          utf8Length(verification.mode.value.expectedIssuerConstraint?.value ?? "") +
          utf8Length(verification.mode.value.expectedSubjectConstraint?.value ?? "") : 0,
      );
      const request = create(JoseOperationRequestSchema, {
        operation: {
          case: "jwtVerify",
          value: {
            compact: options.compact,
            jwkJson: jwk,
            publicKey,
            headerPolicy,
            verification,
          },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jwtVerify") return claimsOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      for (const owned of owners) owned.fill(0);
    }
  },

  encryptJwe(options: ReallyMeJoseEncryptJweOptions): string {
    ensureObjectFields(options, ENCRYPT_JWE_FIELDS);
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
    if (options.compressionAlgorithm !== undefined) {
      validateAlgorithm(options.compressionAlgorithm, [JoseJweCompressionAlgorithm.DEFLATE]);
    }
    const owners: Uint8Array[] = [];
    try {
      const key = ownedBytes(options.key, owners);
      const plaintext = ownedBytes(options.plaintext, owners);
      const apu = options.agreementPartyUInfo === undefined ? undefined : ownedBytes(options.agreementPartyUInfo, owners);
      const apv = options.agreementPartyVInfo === undefined ? undefined : ownedBytes(options.agreementPartyVInfo, owners);
      const keyIdentifier = optionalHeaderString(options.keyIdentifier);
      const type = optionalHeaderString(options.type);
      const contentType = optionalHeaderString(options.contentType);
      ensureAggregateLength(
        key.length,
        plaintext.length,
        apu?.length ?? 0,
        apv?.length ?? 0,
        utf8Length(keyIdentifier ?? ""),
        utf8Length(type ?? ""),
        utf8Length(contentType ?? ""),
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
            compressionAlgorithm: options.compressionAlgorithm
              ?? JoseJweCompressionAlgorithm.UNSPECIFIED,
          },
        },
      });
      return withResponse(request, (response) => {
        const operation = response.response;
        if (operation.case === "jweEncrypt") return compactOutcome(operation.value.outcome);
        return malformedProviderResponse();
      });
    } finally {
      for (const owned of owners) owned.fill(0);
    }
  },

  decryptJwe(options: ReallyMeJoseDecryptJweOptions): Uint8Array {
    ensureObjectFields(options, DECRYPT_JWE_FIELDS);
    ensureString(options.compact);
    if (options.headerPolicy !== undefined) ensureObjectFields(options.headerPolicy, JWE_HEADER_POLICY_FIELDS);
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
    const owners: Uint8Array[] = [];
    try {
      const key = ownedBytes(options.key, owners);
      const expectedApu = options.headerPolicy?.expectedAgreementPartyUInfo === undefined
        ? undefined
        : ownedBytes(options.headerPolicy.expectedAgreementPartyUInfo, owners);
      const expectedApv = options.headerPolicy?.expectedAgreementPartyVInfo === undefined
        ? undefined
        : ownedBytes(options.headerPolicy.expectedAgreementPartyVInfo, owners);
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
      for (const owned of owners) owned.fill(0);
    }
  },
});
