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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseInspectedCompactJws) {
  ReallyMeJOSEMemory.clearOwned(&message.protectedHeaderJson)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  ReallyMeJOSEMemory.clearOwned(&message.signature)
  message = ReallyMeProtoJoseInspectedCompactJws()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseCompactResult) {
  message = ReallyMeProtoJoseCompactResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseVerifyResult) {
  ReallyMeJOSEMemory.clearOwned(&message.protectedHeaderJson)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  message = ReallyMeProtoJoseVerifyResult()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseExpectedString) {
  message = ReallyMeProtoJoseExpectedString()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseExpectedBytes) {
  ReallyMeJOSEMemory.clearOwned(&message.value)
  message = ReallyMeProtoJoseExpectedBytes()
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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseSecretBytes) {
  ReallyMeJOSEMemory.clearOwned(&message.value)
  message = ReallyMeProtoJoseSecretBytes()
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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseContractInfoResponse) {
  switch message.outcome {
  case .result: clearSensitiveFields(&message.result)
  case .error: clearSensitiveFields(&message.error)
  case nil: break
  }
  message = ReallyMeProtoJoseContractInfoResponse()
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
