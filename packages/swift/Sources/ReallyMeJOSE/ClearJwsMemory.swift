// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import ReallyMeJOSEProto

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsSignWithProviderRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.protectedHeaderJson)
  ReallyMeJOSEMemory.clearOwned(&message.payload)
  message = ReallyMeProtoJoseJwsSignWithProviderRequest()
}

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsInspectRequest) {
  message = ReallyMeProtoJoseJwsInspectRequest()
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

func clearSensitiveFields(_ message: inout ReallyMeProtoJoseJwsVerifyRequest) {
  ReallyMeJOSEMemory.clearOwned(&message.publicKey)
  message = ReallyMeProtoJoseJwsVerifyRequest()
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
