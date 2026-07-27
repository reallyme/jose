// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

public enum ReallyMeJOSESignatureAlgorithm: Sendable, Equatable {
  case edDSA
  case es256
}

public enum ReallyMeJOSEJWEKeyManagementAlgorithm: Sendable, Equatable {
  case direct
  case ecdhESP256
  case ecdhESP384
  case ecdhESP521
}

public enum ReallyMeJOSEJWEContentEncryptionAlgorithm: Sendable, Equatable {
  case a128GCM
  case a192GCM
  case a256GCM
}

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

public struct ReallyMeJOSEJWTTemporalPolicy: Sendable, Equatable {
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

  public init(
    requireKeyIdentifier: Bool = false,
    expectedKeyIdentifier: String? = nil,
    expectedType: String? = nil,
    expectedContentType: String? = nil,
    expectedAgreementPartyUInfo: [UInt8]? = nil,
    expectedAgreementPartyVInfo: [UInt8]? = nil
  ) {
    self.requireKeyIdentifier = requireKeyIdentifier
    self.expectedKeyIdentifier = expectedKeyIdentifier
    self.expectedType = expectedType
    self.expectedContentType = expectedContentType
    self.expectedAgreementPartyUInfo = expectedAgreementPartyUInfo
    self.expectedAgreementPartyVInfo = expectedAgreementPartyVInfo
  }
}
