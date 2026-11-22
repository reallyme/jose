// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import ReallyMeJOSEProto

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
