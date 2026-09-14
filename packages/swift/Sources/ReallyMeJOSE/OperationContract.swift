// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeJOSEProto

func sdkError(_ error: ReallyMeProtoJoseError) throws(ReallyMeJOSEError) -> ReallyMeJOSEError {
  guard error.unknownFields.data.isEmpty else {
    throw ReallyMeJOSEError.malformedProviderResponse
  }
  let branch: ReallyMeJOSEErrorBranch
  let protoReason: ReallyMeProtoJoseErrorReason
  switch error.error {
  case .primitive(let value):
    guard value.unknownFields.data.isEmpty else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    branch = .primitive
    protoReason = value.reason
  case .provider(let value):
    guard value.unknownFields.data.isEmpty else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    branch = .provider
    protoReason = value.reason
  case .backend(let value):
    guard value.unknownFields.data.isEmpty else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    branch = .backend
    protoReason = value.reason
  case nil:
    throw ReallyMeJOSEError.malformedProviderResponse
  }
  guard let reason = ReallyMeJOSEErrorReason(rawValue: protoReason.rawValue) else {
    throw ReallyMeJOSEError.malformedProviderResponse
  }
  try reason.validate(branch: branch)
  return .jose(branch: branch, reason: reason)
}
