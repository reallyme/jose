// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import type {
  ReallyMeJoseDecryptJweOptions,
  ReallyMeJoseEncryptJweOptions,
  ReallyMeJoseJweHeaderPolicy,
  ReallyMeJoseJwtHeaderOptions,
  ReallyMeJoseJwtHeaderPolicy,
  ReallyMeJoseJwtClaimsPolicy,
  ReallyMeJoseSignJwsOptions,
  ReallyMeJoseSignJwtOptions,
  ReallyMeJoseVerifyJwsOptions,
  ReallyMeJoseVerifyJwtOptions,
} from "./facade.js";

// Keep runtime validation total over each facade view. A new interface property
// must be classified here before TypeScript will accept the boundary adapter.
export const SIGN_JWS_FIELDS = Object.freeze({
  algorithm: true, privateKey: true, payload: true,
} satisfies Record<keyof ReallyMeJoseSignJwsOptions, true>);
export const VERIFY_JWS_FIELDS = Object.freeze({
  algorithm: true, compact: true, publicKey: true,
} satisfies Record<keyof ReallyMeJoseVerifyJwsOptions, true>);
export const SIGN_JWT_FIELDS = Object.freeze({
  claimsJson: true, jwkJson: true, privateKey: true, headerOptions: true,
} satisfies Record<keyof ReallyMeJoseSignJwtOptions, true>);
export const VERIFY_JWT_FIELDS = Object.freeze({
  compact: true, jwkJson: true, publicKey: true, headerPolicy: true,
  verification: true,
} satisfies Record<keyof ReallyMeJoseVerifyJwtOptions, true>);
export const ENCRYPT_JWE_FIELDS = Object.freeze({
  keyManagementAlgorithm: true, contentEncryptionAlgorithm: true, key: true,
  plaintext: true, keyIdentifier: true, agreementPartyUInfo: true,
  agreementPartyVInfo: true, type: true, contentType: true, compressionAlgorithm: true,
} satisfies Record<keyof ReallyMeJoseEncryptJweOptions, true>);
export const DECRYPT_JWE_FIELDS = Object.freeze({
  compact: true, keyManagementAlgorithm: true, contentEncryptionAlgorithm: true,
  key: true, headerPolicy: true,
} satisfies Record<keyof ReallyMeJoseDecryptJweOptions, true>);
export const JWT_HEADER_OPTION_FIELDS = Object.freeze({
  type: true,
} satisfies Record<keyof ReallyMeJoseJwtHeaderOptions, true>);
export const JWT_HEADER_POLICY_FIELDS = Object.freeze({
  allowMissingType: true, allowEmbeddedKeyHeaders: true, acceptedTypes: true,
} satisfies Record<keyof ReallyMeJoseJwtHeaderPolicy, true>);
export const JWT_CLAIMS_POLICY_FIELDS = Object.freeze({
  requireExpiration: true, requireNotBefore: true, requireIssuedAt: true,
  clockSkewSeconds: true, maximumFutureIssuedAtSkewSeconds: true,
  verificationTimeUnixSeconds: true, expectedAudience: true,
  expectedIssuer: true, expectedSubject: true,
} satisfies Record<keyof ReallyMeJoseJwtClaimsPolicy, true>);
export const JWE_HEADER_POLICY_FIELDS = Object.freeze({
  requireKeyIdentifier: true, expectedKeyIdentifier: true, expectedType: true,
  expectedContentType: true, expectedAgreementPartyUInfo: true,
  expectedAgreementPartyVInfo: true, allowedCompressionAlgorithms: true,
} satisfies Record<keyof ReallyMeJoseJweHeaderPolicy, true>);
