// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import ReallyMeJOSEProto

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseError) {
  switch message.error {
  case .primitive: clearSensitiveFields(&message.primitive)
  case .provider: clearSensitiveFields(&message.provider)
  case .backend: clearSensitiveFields(&message.backend)
  case nil: break
  }
  message = ReallyMeProtoJoseError()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJosePrimitiveError) {
  message = ReallyMeProtoJosePrimitiveError()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseProviderError) {
  message = ReallyMeProtoJoseProviderError()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseBackendError) {
  message = ReallyMeProtoJoseBackendError()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseOperationResponse) {
  switch message.response {
  case .boundaryError: clearSensitiveFields(&message.boundaryError)
  case .jwsSign: clearSensitiveFields(&message.jwsSign)
  case .jwsVerify: clearSensitiveFields(&message.jwsVerify)
  case .jwtEncodeUnsigned: clearSensitiveFields(&message.jwtEncodeUnsigned)
  case .jwtDecodeUnsigned: clearSensitiveFields(&message.jwtDecodeUnsigned)
  case .jwtSign: clearSensitiveFields(&message.jwtSign)
  case .jwtVerify: clearSensitiveFields(&message.jwtVerify)
  case .jweEncrypt: clearSensitiveFields(&message.jweEncrypt)
  case .jweDecrypt: clearSensitiveFields(&message.jweDecrypt)
  case .signatureSign: clearSensitiveFields(&message.signatureSign)
  case .signatureVerify: clearSensitiveFields(&message.signatureVerify)
  case .signatureSuiteInfo: clearSensitiveFields(&message.signatureSuiteInfo)
  case .jwsSignWithProvider: clearSensitiveFields(&message.jwsSignWithProvider)
  case .jwsVerifyWithProvider: clearSensitiveFields(&message.jwsVerifyWithProvider)
  case .jwsInspect: clearSensitiveFields(&message.jwsInspect)
  case .jwtSignWithProvider: clearSensitiveFields(&message.jwtSignWithProvider)
  case .jwtClaimsParse: clearSensitiveFields(&message.jwtClaimsParse)
  case .jweDeriveKey: clearSensitiveFields(&message.jweDeriveKey)
  case .jweEncryptWithProvider: clearSensitiveFields(&message.jweEncryptWithProvider)
  case .jweDecryptWithProvider: clearSensitiveFields(&message.jweDecryptWithProvider)
  case .jwkThumbprintSha256: clearSensitiveFields(&message.jwkThumbprintSha256)
  case .contractInfo: clearSensitiveFields(&message.contractInfo)
  case nil: break
  }
  message = ReallyMeProtoJoseOperationResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseOperationRequest) {
  switch message.operation {
  case .jwsSign: clearSensitiveFields(&message.jwsSign)
  case .jwsVerify: clearSensitiveFields(&message.jwsVerify)
  case .jwtEncodeUnsigned: clearSensitiveFields(&message.jwtEncodeUnsigned)
  case .jwtDecodeUnsigned: clearSensitiveFields(&message.jwtDecodeUnsigned)
  case .jwtSign: clearSensitiveFields(&message.jwtSign)
  case .jwtVerify: clearSensitiveFields(&message.jwtVerify)
  case .jweEncrypt: clearSensitiveFields(&message.jweEncrypt)
  case .jweDecrypt: clearSensitiveFields(&message.jweDecrypt)
  case .signatureSign: clearSensitiveFields(&message.signatureSign)
  case .signatureVerify: clearSensitiveFields(&message.signatureVerify)
  case .signatureSuiteInfo: clearSensitiveFields(&message.signatureSuiteInfo)
  case .jwsSignWithProvider: clearSensitiveFields(&message.jwsSignWithProvider)
  case .jwsVerifyWithProvider: clearSensitiveFields(&message.jwsVerifyWithProvider)
  case .jwsInspect: clearSensitiveFields(&message.jwsInspect)
  case .jwtSignWithProvider: clearSensitiveFields(&message.jwtSignWithProvider)
  case .jwtClaimsParse: clearSensitiveFields(&message.jwtClaimsParse)
  case .jweDeriveKey: clearSensitiveFields(&message.jweDeriveKey)
  case .jweEncryptWithProvider: clearSensitiveFields(&message.jweEncryptWithProvider)
  case .jweDecryptWithProvider: clearSensitiveFields(&message.jweDecryptWithProvider)
  case .jwkThumbprintSha256: clearSensitiveFields(&message.jwkThumbprintSha256)
  case .contractInfo: clearSensitiveFields(&message.contractInfo)
  case nil: break
  }
  message = ReallyMeProtoJoseOperationRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsSignWithProviderRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.protectedHeaderJson)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  message = ReallyMeProtoJoseJwsSignWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsInspectRequest) {
  message = ReallyMeProtoJoseJwsInspectRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseInspectedCompactJws) {
  ReallyMeJOSEMemory.clearOwned(&message.protectedHeaderJson)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  ReallyMeJOSEMemory.clearOwned(&message.signature)
  message = ReallyMeProtoJoseInspectedCompactJws()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsInspectResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwsInspectResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsVerifyWithProviderRequest) {
  if message.hasInput { clearSensitiveFields(&message.input) }
  message = ReallyMeProtoJoseJwsVerifyWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsSignRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.privateKey)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  message = ReallyMeProtoJoseJwsSignRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseCompactResult) {
  message = ReallyMeProtoJoseCompactResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsVerifyRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.publicKey)
  message = ReallyMeProtoJoseJwsVerifyRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseVerifyResult) {
  ReallyMeJOSEMemory.clearOwned(&message.protectedHeaderJson)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  message = ReallyMeProtoJoseVerifyResult()
}

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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweEncryptRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.key)
  ReallyMeJOSEMemory.clearOwned(&message.plaintext)
  ReallyMeJOSEMemory.clearOwned(&message.apu)
  ReallyMeJOSEMemory.clearOwned(&message.apv)
  message = ReallyMeProtoJoseJweEncryptRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweDecryptRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.key)
  if message.hasHeaderPolicy { clearSensitiveFields(&message.headerPolicy) }
  message = ReallyMeProtoJoseJweDecryptRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseExpectedString) {
  message = ReallyMeProtoJoseExpectedString()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseExpectedBytes) {
  ReallyMeJOSEMemory.clearOwned(&message.value)
  message = ReallyMeProtoJoseExpectedBytes()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweHeaderValidationPolicy) {
  if message.hasExpectedKid { clearSensitiveFields(&message.expectedKid) }
  if message.hasExpectedTyp { clearSensitiveFields(&message.expectedTyp) }
  if message.hasExpectedCty { clearSensitiveFields(&message.expectedCty) }
  if message.hasExpectedApu { clearSensitiveFields(&message.expectedApu) }
  if message.hasExpectedApv { clearSensitiveFields(&message.expectedApv) }
  message = ReallyMeProtoJoseJweHeaderValidationPolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwePlaintextResult) {
  ReallyMeJOSEMemory.clearOwned(&message.plaintext)
  message = ReallyMeProtoJoseJwePlaintextResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsSignResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwsSignResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsVerifyResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwsVerifyResponse()
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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweEncryptResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJweEncryptResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweDecryptResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJweDecryptResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureSignRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.privateKey)
  ReallyMeJOSEMemory.clearOwned(&message.signingInput)
  message = ReallyMeProtoJoseSignatureSignRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureVerifyRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.signingInput)
  ReallyMeJOSEMemory.clearOwned(&message.publicKey)
  ReallyMeJOSEMemory.clearOwned(&message.signature)
  message = ReallyMeProtoJoseSignatureVerifyRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureResult) {
  ReallyMeJOSEMemory.clearOwned(&message.signature)
  message = ReallyMeProtoJoseSignatureResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseValidationResult) {
  message = ReallyMeProtoJoseValidationResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureSuiteInfoRequest) {
  message = ReallyMeProtoJoseSignatureSuiteInfoRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureSuiteInfoResult) {
  message = ReallyMeProtoJoseSignatureSuiteInfoResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignWithProviderRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.claimsJson)
  ReallyMeJOSEMemory.clearOwned(&message.jwkJson)
  if message.hasHeaderOptions { clearSensitiveFields(&message.headerOptions) }
  message = ReallyMeProtoJoseJwtSignWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweProtectedHeader) {
  ReallyMeJOSEMemory.clearOwned(&message.apu)
  ReallyMeJOSEMemory.clearOwned(&message.apv)
  ReallyMeJOSEMemory.clearOwned(&message.epkJson)
  message = ReallyMeProtoJoseJweProtectedHeader()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweDeriveKeyRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.sharedSecret)
  if message.hasHeader { clearSensitiveFields(&message.header) }
  message = ReallyMeProtoJoseJweDeriveKeyRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSecretBytes) {
  ReallyMeJOSEMemory.clearOwned(&message.value)
  message = ReallyMeProtoJoseSecretBytes()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweEncryptWithProviderRequest) {
  if message.hasParameters { clearSensitiveFields(&message.parameters) }
  message = ReallyMeProtoJoseJweEncryptWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwePolicy) {
  if message.hasHeaderPolicy { clearSensitiveFields(&message.headerPolicy) }
  message = ReallyMeProtoJoseJwePolicy()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweDecryptWithProviderRequest) {
  if message.hasPolicy { clearSensitiveFields(&message.policy) }
  message = ReallyMeProtoJoseJweDecryptWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseContractInfoRequest) {
  message = ReallyMeProtoJoseContractInfoRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseContractInfoResult) {
  message = ReallyMeProtoJoseContractInfoResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureSignResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseSignatureSignResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureVerifyResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseSignatureVerifyResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSignatureSuiteInfoResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseSignatureSuiteInfoResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwtSignWithProviderResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwtSignWithProviderResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweDeriveKeyResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJweDeriveKeyResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweEncryptWithProviderResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJweEncryptWithProviderResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJweDecryptWithProviderResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJweDecryptWithProviderResponse()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseContractInfoResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseContractInfoResponse()
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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintSha256Request) {
  switch message.key {
  case .ec: clearSensitiveFields(&message.ec)
  case .okp: clearSensitiveFields(&message.okp)
  case .rsa: clearSensitiveFields(&message.rsa)
  case .oct: clearSensitiveFields(&message.oct)
  case nil: break
  }
  message = ReallyMeProtoJoseJwkThumbprintSha256Request()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintEcMembers) {
  message = ReallyMeProtoJoseJwkThumbprintEcMembers()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintOkpMembers) {
  message = ReallyMeProtoJoseJwkThumbprintOkpMembers()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintRsaMembers) {
  message = ReallyMeProtoJoseJwkThumbprintRsaMembers()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintOctMembers) {
  message = ReallyMeProtoJoseJwkThumbprintOctMembers()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintSha256Result) {
  ReallyMeJOSEMemory.clearOwned(&message.digest)
  message = ReallyMeProtoJoseJwkThumbprintSha256Result()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwkThumbprintSha256Response) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseJwkThumbprintSha256Response()
}
