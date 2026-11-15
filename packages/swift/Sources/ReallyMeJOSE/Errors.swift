// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeJOSEProto

/// Audit-safe Swift errors. No case contains secrets, PII, raw buffers, paths, or backend text.
public enum ReallyMeJOSEError: Error, Sendable, Equatable {
  case jose(branch: ReallyMeJOSEErrorBranch, reason: ReallyMeJOSEErrorReason)
  case unsupportedPlatform
  case nativeLibraryNotFound
  case nativeLibraryLoadFailed
  case nativeSymbolMissing
  case incompatibleABI
  case malformedProviderResponse

  /// Stable SDK error code defined in the protobuf contract.
  public var code: ReallyMeProtoJoseSdkErrorCode {
    switch self {
    case .jose: .joseFailure
    case .unsupportedPlatform: .unsupportedPlatform
    case .nativeLibraryNotFound: .nativeLibraryNotFound
    case .nativeLibraryLoadFailed: .nativeLibraryLoadFailed
    case .nativeSymbolMissing: .nativeSymbolMissing
    case .incompatibleABI: .incompatibleAbi
    case .malformedProviderResponse: .malformedProviderResponse
    }
  }
}
