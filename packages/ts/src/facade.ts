// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//

import { create } from "@bufbuild/protobuf";
import {
  JoseJweContentEncryptionAlgorithm,
  JoseJweKeyManagementAlgorithm,
  JoseOperationRequestSchema,
  JoseSignatureAlgorithm,
} from "./proto/generated/reallyme/jose/v1/jose_pb.js";
import {
  ensureAggregateLength,
  ensureObject,
  ensureString,
  utf8Length,
} from "./validate.js";
import {
  claimsOutcome,
  compactOutcome,
  jweHeaderPolicy,
  jwtHeaderPolicy,
  jwtHeaderPolicyLength,
  jwtTemporalPolicy,
  jwtTemporalPolicyLength,
  malformedProviderResponse,
  optionalBoolean,
  optionalString,
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


export const ReallyMeJose = Object.freeze({
  signJws(options: ReallyMeJoseSignJwsOptions): string {
    ensureObject(options);
    validateAlgorithm(options.algorithm, [JoseSignatureAlgorithm.EDDSA, JoseSignatureAlgorithm.ES256]);
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
    ensureObject(options);
    validateAlgorithm(options.algorithm, [JoseSignatureAlgorithm.EDDSA, JoseSignatureAlgorithm.ES256]);
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
    ensureObject(options);
    const owners: Uint8Array[] = [];
    try {
      const claims = ownedBytes(options.claimsJson, owners);
      const jwk = ownedBytes(options.jwkJson, owners);
      const privateKey = ownedBytes(options.privateKey, owners);
      const type = optionalString(options.type);
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
      for (const owned of owners) owned.fill(0);
    }
  },

  verifyJwt(options: ReallyMeJoseVerifyJwtOptions): Uint8Array {
    ensureObject(options);
    ensureString(options.compact);
    const owners: Uint8Array[] = [];
    try {
      const jwk = ownedBytes(options.jwkJson, owners);
      const publicKey = ownedBytes(options.publicKey, owners);
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
      for (const owned of owners) owned.fill(0);
    }
  },

  encryptJwe(options: ReallyMeJoseEncryptJweOptions): string {
    ensureObject(options);
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
      const plaintext = ownedBytes(options.plaintext, owners);
      const apu = ownedBytes(options.agreementPartyUInfo === undefined ? new Uint8Array() : options.agreementPartyUInfo, owners);
      const apv = ownedBytes(options.agreementPartyVInfo === undefined ? new Uint8Array() : options.agreementPartyVInfo, owners);
      const keyIdentifier = optionalString(options.keyIdentifier);
      const type = optionalString(options.type);
      const contentType = optionalString(options.contentType);
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
      for (const owned of owners) owned.fill(0);
    }
  },

  decryptJwe(options: ReallyMeJoseDecryptJweOptions): Uint8Array {
    ensureObject(options);
    ensureString(options.compact);
    if (options.headerPolicy !== undefined) ensureObject(options.headerPolicy);
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
