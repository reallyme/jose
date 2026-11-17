// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

enum JoseContractValues {
  static let nativeAbiVersion: UInt32 = 1
  static let compactBytes: Int = 1_048_576
  static let protoJsonBytes: Int = 1_572_864
  static let responseOverheadBytes: Int = 32
  static let jwkThumbprintMemberBytes: Int = 8_192
  static let protoRecursionDepth: Int = 64
  static let temporalSkewSeconds: UInt64 = 300
  static let defaultTemporalSkewSeconds: UInt64 = 60
  static let acceptedTypeValues: Int = 32
}

/// Schema-derived stable reason codes without caller data.
public enum ReallyMeJOSEErrorReason: Int, Sendable, Equatable {
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
  case jweInvalidHeader = 220
  case jweUnsupportedKeyManagementAlgorithm = 221
  case jweUnsupportedContentEncryptionAlgorithm = 222
  case jweMissingRequiredHeaderParameter = 223
  case jweHeaderPolicyMismatch = 224
  case jweKidPolicyMismatch = 225
  case jweApuPolicyMismatch = 226
  case jweApvPolicyMismatch = 227
  case jweUnsupportedCompressionAlgorithm = 228
  case jweInvalidEncryptedKey = 240
  case jweInvalidContentEncryptionKey = 241
  case jweInvalidContentCipherInput = 242
  case jweDecryptFailed = 243
  case jweEncryptFailed = 244
  case jweInvalidKeyAgreementKey = 245
  case jweInvalidSharedSecret = 247
  case jweInvalidPayloadJSON = 260
  case jweCompressionFailed = 261
  case jweDecompressionFailed = 262
  case jweDecompressedPlaintextTooLarge = 263
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
  case jwkThumbprintMissingMember = 400
  case jwkThumbprintInvalidMemberType = 401
  case jwkThumbprintUnsupportedKeyType = 402
  case jwkThumbprintInvalidJSONObject = 403
  case jwkThumbprintMemberTooLarge = 404
  case commonMalformedProtobuf = 700
  case commonMalformedJSON = 701
  case commonMissingOperation = 702
  case commonResourceLimitExceeded = 703
  case commonLengthOverflow = 704
  case commonInvalidCompact = 705
  case commonInvalidEncoding = 706
  case providerUnavailable = 800
  case providerUnsupported = 801
  case providerRandomnessUnavailable = 802
  case backendInternal = 900
  case backendJSONSerialization = 901
  case backendKeyDerivationFailed = 902
  case backendJwkThumbprintSerialization = 940
  case backendJwkThumbprintAllocation = 941

  var branch: ReallyMeJOSEErrorBranch {
    switch self {
    case .jwsInvalidPayloadUtf8: .primitive
    case .jwsBadPayloadBase64: .primitive
    case .jwsBadHeaderBase64: .primitive
    case .jwsBadHeaderUtf8: .primitive
    case .jwsHeaderMismatch: .primitive
    case .jwsBadSignatureBase64: .primitive
    case .jwsBadRawSignature: .primitive
    case .jwsInvalidSignature: .primitive
    case .jwsSignFailed: .primitive
    case .jwsBadDerSignature: .primitive
    case .jweInvalidHeader: .primitive
    case .jweUnsupportedKeyManagementAlgorithm: .primitive
    case .jweUnsupportedContentEncryptionAlgorithm: .primitive
    case .jweMissingRequiredHeaderParameter: .primitive
    case .jweHeaderPolicyMismatch: .primitive
    case .jweKidPolicyMismatch: .primitive
    case .jweApuPolicyMismatch: .primitive
    case .jweApvPolicyMismatch: .primitive
    case .jweUnsupportedCompressionAlgorithm: .primitive
    case .jweInvalidEncryptedKey: .primitive
    case .jweInvalidContentEncryptionKey: .primitive
    case .jweInvalidContentCipherInput: .primitive
    case .jweDecryptFailed: .primitive
    case .jweEncryptFailed: .primitive
    case .jweInvalidKeyAgreementKey: .primitive
    case .jweInvalidSharedSecret: .primitive
    case .jweInvalidPayloadJSON: .primitive
    case .jweCompressionFailed: .primitive
    case .jweDecompressionFailed: .primitive
    case .jweDecompressedPlaintextTooLarge: .primitive
    case .jwtInvalidHeader: .primitive
    case .jwtUnsupportedAlgorithm: .primitive
    case .jwtAlgorithmMismatch: .primitive
    case .jwtMissingAlgorithm: .primitive
    case .jwtMissingPrivateKey: .primitive
    case .jwtMissingPublicKey: .primitive
    case .jwtKidPolicyMismatch: .primitive
    case .jwtPublicKeyMismatch: .primitive
    case .jwtInvalidPublicKey: .primitive
    case .jwtInvalidJwk: .primitive
    case .jwtInvalidSignature: .primitive
    case .jwtCryptoFailed: .primitive
    case .jwtInvalidClaims: .primitive
    case .jwtSerializationFailed: .primitive
    case .jwtMissingRequiredTemporalClaim: .primitive
    case .jwtInvalidTemporalClaimValue: .primitive
    case .jwtExpired: .primitive
    case .jwtNotYetValid: .primitive
    case .jwtIssuedAtInFuture: .primitive
    case .jwtInvalidVerificationTime: .primitive
    case .jwtInvalidVerificationPolicy: .primitive
    case .jwtSigningKeyMismatch: .primitive
    case .jwtMissingRequiredRegisteredClaim: .primitive
    case .jwtInvalidRegisteredClaimValue: .primitive
    case .jwtAudienceMismatch: .primitive
    case .jwtIssuerMismatch: .primitive
    case .jwtSubjectMismatch: .primitive
    case .jwkThumbprintMissingMember: .primitive
    case .jwkThumbprintInvalidMemberType: .primitive
    case .jwkThumbprintUnsupportedKeyType: .primitive
    case .jwkThumbprintInvalidJSONObject: .primitive
    case .jwkThumbprintMemberTooLarge: .primitive
    case .commonMalformedProtobuf: .primitive
    case .commonMalformedJSON: .primitive
    case .commonMissingOperation: .primitive
    case .commonResourceLimitExceeded: .primitive
    case .commonLengthOverflow: .primitive
    case .commonInvalidCompact: .primitive
    case .commonInvalidEncoding: .primitive
    case .providerUnavailable: .provider
    case .providerUnsupported: .provider
    case .providerRandomnessUnavailable: .provider
    case .backendInternal: .backend
    case .backendJSONSerialization: .backend
    case .backendKeyDerivationFailed: .backend
    case .backendJwkThumbprintSerialization: .backend
    case .backendJwkThumbprintAllocation: .backend
    }
  }

  func validate(branch: ReallyMeJOSEErrorBranch) throws(ReallyMeJOSEError) {
    guard self.branch == branch else { throw .malformedProviderResponse }
  }
}
