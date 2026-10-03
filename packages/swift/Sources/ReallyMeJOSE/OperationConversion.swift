// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeJOSEProto

func protoSignatureAlgorithm(
  _ value: ReallyMeJOSESignatureAlgorithm
) -> ReallyMeProtoJoseSignatureAlgorithm {
  switch value {
  case .edDSA: .eddsa
  case .es256: .es256
  }
}

func protoKeyManagementAlgorithm(
  _ value: ReallyMeJOSEJWEKeyManagementAlgorithm
) -> ReallyMeProtoJoseJweKeyManagementAlgorithm {
  switch value {
  case .direct: .direct
  case .ecdhESP256: .ecdhEsP256
  case .ecdhESP384: .ecdhEsP384
  case .ecdhESP521: .ecdhEsP521
  }
}

func protoContentEncryptionAlgorithm(
  _ value: ReallyMeJOSEJWEContentEncryptionAlgorithm
) -> ReallyMeProtoJoseJweContentEncryptionAlgorithm {
  switch value {
  case .a128GCM: .a128Gcm
  case .a192GCM: .a192Gcm
  case .a256GCM: .a256Gcm
  }
}

func protoCompressionAlgorithm(
  _ value: ReallyMeJOSEJWECompressionAlgorithm
) -> ReallyMeProtoJoseJweCompressionAlgorithm {
  switch value {
  case .deflate: .deflate
  }
}

func protoJWTHeaderPolicy(
  _ value: ReallyMeJOSEJWTHeaderPolicy
) -> ReallyMeProtoJoseJwtHeaderValidationPolicy {
  var result = ReallyMeProtoJoseJwtHeaderValidationPolicy()
  result.allowMissingTyp = value.allowMissingTyp
  result.allowEmbeddedKeyHeader = value.allowEmbeddedKeyHeader
  result.acceptedTypValues = value.acceptedTypValues
  return result
}

func protoJWTTemporalPolicy(
  _ value: ReallyMeJOSEJWTTemporalPolicy
) throws(ReallyMeJOSEError) -> ReallyMeProtoJoseJwtTemporalValidationPolicy {
  if value.expectedIssuer == "" || value.expectedSubject == "" {
    throw .jose(branch: .primitive, reason: .jwtInvalidVerificationPolicy)
  }
  var result = ReallyMeProtoJoseJwtTemporalValidationPolicy()
  result.requireExp = value.requireExpiration
  result.requireNbf = value.requireNotBefore
  result.requireIat = value.requireIssuedAt
  result.clockSkewSeconds = value.clockSkewSeconds
  result.maxFutureIatSkewSeconds = value.maximumFutureIssuedAtSkewSeconds
  result.nowUnix = value.nowUnix
  result.expectedAudience = value.expectedAudience
  if let issuer = value.expectedIssuer {
    var constraint = ReallyMeProtoJoseExpectedString()
    constraint.value = issuer
    result.expectedIssuerConstraint = constraint
  }
  if let subject = value.expectedSubject {
    var constraint = ReallyMeProtoJoseExpectedString()
    constraint.value = subject
    result.expectedSubjectConstraint = constraint
  }
  return result
}

func protoJWEHeaderPolicy(
  _ value: ReallyMeJOSEJWEHeaderPolicy
) -> ReallyMeProtoJoseJweHeaderValidationPolicy {
  var result = ReallyMeProtoJoseJweHeaderValidationPolicy()
  result.requireKid = value.requireKeyIdentifier
  if let expected = value.expectedKeyIdentifier {
    var wrapped = ReallyMeProtoJoseExpectedString()
    wrapped.value = expected
    result.expectedKid = wrapped
  }
  if let expected = value.expectedType {
    var wrapped = ReallyMeProtoJoseExpectedString()
    wrapped.value = expected
    result.expectedTyp = wrapped
  }
  if let expected = value.expectedContentType {
    var wrapped = ReallyMeProtoJoseExpectedString()
    wrapped.value = expected
    result.expectedCty = wrapped
  }
  if let expected = value.expectedAgreementPartyUInfo {
    var wrapped = ReallyMeProtoJoseExpectedBytes()
    wrapped.value = ReallyMeJOSEMemory.ownedData(expected)
    result.expectedApu = wrapped
  }
  if let expected = value.expectedAgreementPartyVInfo {
    var wrapped = ReallyMeProtoJoseExpectedBytes()
    wrapped.value = ReallyMeJOSEMemory.ownedData(expected)
    result.expectedApv = wrapped
  }
  result.allowedCompressionAlgorithms = value.allowedCompressionAlgorithms.map(
    protoCompressionAlgorithm)
  return result
}

func wipeRequest(_ request: inout ReallyMeProtoJoseOperationRequest) {
  switch request.operation {
  case .jwsSign:
    ReallyMeJOSEMemory.clearOwned(&request.jwsSign.privateKey)
    ReallyMeJOSEMemory.clearOwned(&request.jwsSign.payload)
  case .jwsVerify:
    ReallyMeJOSEMemory.clearOwned(&request.jwsVerify.publicKey)
  case .jwtEncodeUnsigned:
    ReallyMeJOSEMemory.clearOwned(&request.jwtEncodeUnsigned.claimsJson)
  case .jwtDecodeUnsigned:
    break
  case .jwtSign:
    ReallyMeJOSEMemory.clearOwned(&request.jwtSign.claimsJson)
    ReallyMeJOSEMemory.clearOwned(&request.jwtSign.jwkJson)
    ReallyMeJOSEMemory.clearOwned(&request.jwtSign.privateKey)
  case .jwtVerify:
    ReallyMeJOSEMemory.clearOwned(&request.jwtVerify.jwkJson)
    ReallyMeJOSEMemory.clearOwned(&request.jwtVerify.publicKey)
  case .jweEncrypt:
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.key)
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.plaintext)
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.apu)
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.apv)
  case .jweDecrypt:
    ReallyMeJOSEMemory.clearOwned(&request.jweDecrypt.key)
  case nil:
    break
  }
  request.operation = nil
}
