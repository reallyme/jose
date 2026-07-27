// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// The stable generated error branch selected by the Rust semantic core.
public enum ReallyMeJOSEErrorBranch: Sendable, Equatable {
  case primitive
  case provider
  case backend
}

/// Stable JOSE reason codes. Variants intentionally carry no input or backend text.
public enum ReallyMeJOSEErrorReason: Int, Sendable, Equatable {
  case jwsInvalidCompact = 100
  case jwsInputTooLarge = 101
  case jwsLengthOverflow = 102
  case jwsInvalidPayloadUtf8 = 103
  case jwsBadPayloadBase64 = 104
  case jwsBadHeaderBase64 = 120
  case jwsBadHeaderUtf8 = 121
  case jwsHeaderMismatch = 122
  case jwsBadSignatureBase64 = 140
  case jwsBadRawSignature = 141
  case jwsInvalidSignature = 142
  case jwsSignFailed = 160
  case jwsBadDerSignature = 161
  case jweInvalidCompact = 200
  case jweInputTooLarge = 201
  case jweInvalidEncoding = 202
  case jweInvalidHeader = 220
  case jweUnsupportedKeyManagementAlgorithm = 221
  case jweUnsupportedContentEncryptionAlgorithm = 222
  case jweMissingRequiredHeaderParameter = 223
  case jweHeaderPolicyMismatch = 224
  case jweKidPolicyMismatch = 225
  case jweApuPolicyMismatch = 226
  case jweApvPolicyMismatch = 227
  case jweInvalidEncryptedKey = 240
  case jweInvalidContentEncryptionKey = 241
  case jweInvalidContentCipherInput = 242
  case jweDecryptFailed = 243
  case jweEncryptFailed = 244
  case jweInvalidKeyAgreementKey = 245
  case jweLengthOverflow = 246
  case jweInvalidSharedSecret = 247
  case jweInvalidPayloadJson = 260
  case jwtInvalidCompact = 300
  case jwtInputTooLarge = 301
  case jwtBase64URLDecodeFailed = 302
  case jwtLengthOverflow = 303
  case jwtInvalidHeader = 320
  case jwtUnsupportedAlgorithm = 321
  case jwtAlgorithmMismatch = 322
  case jwtMissingAlgorithm = 323
  case jwtMissingPrivateKey = 324
  case jwtMissingPublicKey = 325
  case jwtKidPolicyMismatch = 326
  case jwtPublicKeyMismatch = 327
  case jwtInvalidPublicKey = 328
  case jwtInvalidJwk = 329
  case jwtInvalidSignature = 340
  case jwtCryptoFailed = 341
  case jwtInvalidClaims = 360
  case jwtSerializationFailed = 361
  case jwtMissingRequiredTemporalClaim = 380
  case jwtInvalidTemporalClaimValue = 381
  case jwtExpired = 382
  case jwtNotYetValid = 383
  case jwtIssuedAtInFuture = 384
  case jwtInvalidVerificationTime = 385
  case jwtInvalidVerificationPolicy = 386
  case jwtSigningKeyMismatch = 387
  case jwtMissingRequiredRegisteredClaim = 388
  case jwtInvalidRegisteredClaimValue = 389
  case jwtAudienceMismatch = 390
  case jwtIssuerMismatch = 391
  case jwtSubjectMismatch = 392
  case commonMalformedProtobuf = 700
  case commonMalformedJSON = 701
  case commonMissingOperation = 702
  case commonResourceLimitExceeded = 703
  case providerUnavailable = 800
  case providerUnsupported = 801
  case providerRandomnessUnavailable = 802
  case backendInternal = 900
  case backendJSONSerialization = 901
  case backendKeyDerivationFailed = 902
}

/// Audit-safe Swift errors. No case contains secrets, PII, raw buffers, paths, or backend text.
public enum ReallyMeJOSEError: Error, Sendable, Equatable {
  case jose(branch: ReallyMeJOSEErrorBranch, reason: ReallyMeJOSEErrorReason)
  case unsupportedPlatform
  case nativeLibraryNotFound
  case nativeLibraryLoadFailed
  case nativeSymbolMissing
  case incompatibleABI
  case malformedProviderResponse
}
