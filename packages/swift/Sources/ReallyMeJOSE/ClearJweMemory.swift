// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import ReallyMeJOSEProto

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
