// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeJOSEProto

func protoJWTHeaderPolicy(
  _ value: ReallyMeJOSEJWTHeaderPolicy
) throws(ReallyMeJOSEError) -> ReallyMeProtoJoseJwtHeaderValidationPolicy {
  guard value.acceptedTypValues.count <= JoseContractValues.acceptedTypeValues else {
    throw .jose(branch: .primitive, reason: .commonResourceLimitExceeded)
  }
  var result = ReallyMeProtoJoseJwtHeaderValidationPolicy()
  result.allowMissingTyp = value.allowMissingTyp
  result.allowEmbeddedKeyHeader = value.allowEmbeddedKeyHeader
  result.acceptedTypValues = value.acceptedTypValues
  return result
}

func protoJWTClaimsPolicy(
  _ value: ReallyMeJOSEJWTClaimsPolicy
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
  clearSensitiveFields(&request)
}

func protoJWTVerification(
  _ verification: ReallyMeJOSEJWTVerification
) throws(ReallyMeJOSEError) -> ReallyMeProtoJoseJwtVerificationPolicy {
  var result = ReallyMeProtoJoseJwtVerificationPolicy()
  switch verification {
  case .signatureOnly:
    result.mode = .signatureOnly(ReallyMeProtoJoseJwtSignatureOnlyPolicy())
  case .claims(let policy):
    result.mode = .claims(try protoJWTClaimsPolicy(policy))
  case .temporalOnly(let policy):
    var options = ReallyMeProtoJoseJwtTemporalOptions()
    options.requireExp = policy.requireExpiration
    options.requireNbf = policy.requireNotBefore
    options.requireIat = policy.requireIssuedAt
    options.clockSkewSeconds = policy.clockSkewSeconds
    options.maxFutureIatSkewSeconds = policy.maximumFutureIssuedAtSkewSeconds
    var temporal = ReallyMeProtoJoseJwtTemporalOnlyPolicy()
    temporal.options = options
    temporal.nowUnix = policy.nowUnix
    result.mode = .temporalOnly(temporal)
  }
  return result
}
