// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import ReallyMeJOSEProto

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtEncodeUnsignedRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  message = ReallyMeProtoJoseJwtEncodeUnsignedRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtDecodeUnsignedRequest) {
  message = ReallyMeProtoJoseJwtDecodeUnsignedRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtClaimsResult) {
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  message = ReallyMeProtoJoseJwtClaimsResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  ReallyMeJOSEMemory.clearOwned(&message.jwkJson)
  ReallyMeJOSEMemory.clearOwned(&message.privateKey)
  if message.hasHeaderOptions { clearSensitiveFields(&message.headerOptions) }
  message = ReallyMeProtoJoseJwtSignRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtHeaderEncodeOptions) {
  message = ReallyMeProtoJoseJwtHeaderEncodeOptions()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtVerifyRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.jwkJson)
  ReallyMeJOSEMemory.clearOwned(&message.publicKey)
  if message.hasHeaderPolicy { clearSensitiveFields(&message.headerPolicy) }
  if message.hasVerification { clearSensitiveFields(&message.verification) }
  message = ReallyMeProtoJoseJwtVerifyRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtVerificationPolicy) {
  switch message.mode {
  case .signatureOnly: clearSensitiveFields(&message.signatureOnly)
  case .claims: clearSensitiveFields(&message.claims)
  case .temporalOnly: clearSensitiveFields(&message.temporalOnly)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtVerificationPolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignatureOnlyPolicy) {
  message = ReallyMeProtoJoseJwtSignatureOnlyPolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtTemporalOnlyPolicy) {
  if message.hasOptions { clearSensitiveFields(&message.options) }
  message = ReallyMeProtoJoseJwtTemporalOnlyPolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtTemporalOptions) {
  message = ReallyMeProtoJoseJwtTemporalOptions()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtHeaderValidationPolicy) {
  message = ReallyMeProtoJoseJwtHeaderValidationPolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtTemporalValidationPolicy) {
  if message.hasExpectedIssuerConstraint { clearSensitiveFields(&message.expectedIssuerConstraint) }
  if message.hasExpectedSubjectConstraint {
    clearSensitiveFields(&message.expectedSubjectConstraint)
  }
  message = ReallyMeProtoJoseJwtTemporalValidationPolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtEncodeUnsignedResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtEncodeUnsignedResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtDecodeUnsignedResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtDecodeUnsignedResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtSignResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtVerifyResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtVerifyResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignWithProviderRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  ReallyMeJOSEMemory.clearOwned(&message.jwkJson)
  if message.hasHeaderOptions { clearSensitiveFields(&message.headerOptions) }
  message = ReallyMeProtoJoseJwtSignWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignWithProviderResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtSignWithProviderResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtRegisteredClaims) {
  if message.hasAud { clearSensitiveFields(&message.aud) }
  message = ReallyMeProtoJoseJwtRegisteredClaims()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtAudience) {
  message = ReallyMeProtoJoseJwtAudience()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtClaimsParseRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  message = ReallyMeProtoJoseJwtClaimsParseRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtClaimsParseResult) {
  if message.hasRegistered { clearSensitiveFields(&message.registered) }
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  message = ReallyMeProtoJoseJwtClaimsParseResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtClaimsParseResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtClaimsParseResponse()
}
