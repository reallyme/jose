// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

public struct ReallyMeJOSEJWTHeaderPolicy: Sendable, Equatable {
  public let allowMissingTyp: Bool
  public let allowEmbeddedKeyHeader: Bool
  public let acceptedTypValues: [String]

  public init(
    allowMissingTyp: Bool,
    allowEmbeddedKeyHeader: Bool,
    acceptedTypValues: [String]
  ) {
    self.allowMissingTyp = allowMissingTyp
    self.allowEmbeddedKeyHeader = allowEmbeddedKeyHeader
    self.acceptedTypValues = acceptedTypValues
  }
}

public struct ReallyMeJOSEJWTClaimsPolicy: Sendable, Equatable {
  public let requireExpiration: Bool
  public let requireNotBefore: Bool
  public let requireIssuedAt: Bool
  public let clockSkewSeconds: UInt64
  public let maximumFutureIssuedAtSkewSeconds: UInt64
  public let nowUnix: UInt64
  public let expectedAudience: String
  public let expectedIssuer: String?
  public let expectedSubject: String?

  public init(
    requireExpiration: Bool,
    requireNotBefore: Bool,
    requireIssuedAt: Bool,
    clockSkewSeconds: UInt64,
    maximumFutureIssuedAtSkewSeconds: UInt64,
    nowUnix: UInt64,
    expectedAudience: String,
    expectedIssuer: String? = nil,
    expectedSubject: String? = nil
  ) {
    self.requireExpiration = requireExpiration
    self.requireNotBefore = requireNotBefore
    self.requireIssuedAt = requireIssuedAt
    self.clockSkewSeconds = clockSkewSeconds
    self.maximumFutureIssuedAtSkewSeconds = maximumFutureIssuedAtSkewSeconds
    self.nowUnix = nowUnix
    self.expectedAudience = expectedAudience
    self.expectedIssuer = expectedIssuer
    self.expectedSubject = expectedSubject
  }
}

public struct ReallyMeJOSEJWEHeaderPolicy: Sendable, Equatable {
  public let requireKeyIdentifier: Bool
  public let expectedKeyIdentifier: String?
  public let expectedType: String?
  public let expectedContentType: String?
  public let expectedAgreementPartyUInfo: [UInt8]?
  public let expectedAgreementPartyVInfo: [UInt8]?
  public let allowedCompressionAlgorithms: [ReallyMeJOSEJWECompressionAlgorithm]

  public init(
    requireKeyIdentifier: Bool = false,
    expectedKeyIdentifier: String? = nil,
    expectedType: String? = nil,
    expectedContentType: String? = nil,
    expectedAgreementPartyUInfo: [UInt8]? = nil,
    expectedAgreementPartyVInfo: [UInt8]? = nil,
    allowedCompressionAlgorithms: [ReallyMeJOSEJWECompressionAlgorithm] = []
  ) {
    self.requireKeyIdentifier = requireKeyIdentifier
    self.expectedKeyIdentifier = expectedKeyIdentifier
    self.expectedType = expectedType
    self.expectedContentType = expectedContentType
    self.expectedAgreementPartyUInfo = expectedAgreementPartyUInfo
    self.expectedAgreementPartyVInfo = expectedAgreementPartyVInfo
    self.allowedCompressionAlgorithms = allowedCompressionAlgorithms
  }
}

// These policies can carry user identifiers and correlating protocol values.
// Incidental logging and reflection must not reveal their stored fields.
extension ReallyMeJOSEJWTHeaderPolicy: CustomReflectable {
  public var customMirror: Mirror { Mirror(self, children: [("value", "<redacted>")]) }
}

extension ReallyMeJOSEJWTClaimsPolicy: CustomReflectable {
  public var customMirror: Mirror { Mirror(self, children: [("value", "<redacted>")]) }
}

extension ReallyMeJOSEJWEHeaderPolicy: CustomReflectable {
  public var customMirror: Mirror { Mirror(self, children: [("value", "<redacted>")]) }
}

/// An absent options object selects the standard JWT type. Within an options
/// object, a nil type explicitly omits the protected-header parameter.
public struct ReallyMeJOSEJWTHeaderOptions: Sendable, Equatable, CustomReflectable {
  public let type: String?
  public init(type: String? = nil) { self.type = type }
  public var customMirror: Mirror { Mirror(self, children: [("value", "<redacted>")]) }
}
