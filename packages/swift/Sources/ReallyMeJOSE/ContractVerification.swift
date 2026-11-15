// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

/// Explicit schema verification mode. Temporal-only does not authorize an audience.
public enum ReallyMeJOSEJWTVerification: Sendable, Equatable {
  case signatureOnly
  case claims(ReallyMeJOSEJWTClaimsPolicy)
  case temporalOnly(ReallyMeJOSEJWTTemporalPolicy)
}

public struct ReallyMeJOSEJWTTemporalPolicy: Sendable, Equatable, CustomReflectable {
  public let requireExpiration: Bool
  public let requireNotBefore: Bool
  public let requireIssuedAt: Bool
  public let clockSkewSeconds: UInt64
  public let maximumFutureIssuedAtSkewSeconds: UInt64
  public let nowUnix: UInt64

  public init(
    requireExpiration: Bool,
    requireNotBefore: Bool,
    requireIssuedAt: Bool,
    clockSkewSeconds: UInt64,
    maximumFutureIssuedAtSkewSeconds: UInt64,
    nowUnix: UInt64
  ) {
    self.requireExpiration = requireExpiration
    self.requireNotBefore = requireNotBefore
    self.requireIssuedAt = requireIssuedAt
    self.clockSkewSeconds = clockSkewSeconds
    self.maximumFutureIssuedAtSkewSeconds = maximumFutureIssuedAtSkewSeconds
    self.nowUnix = nowUnix
  }

  public var customMirror: Mirror { Mirror(self, children: [("value", "<redacted>")]) }
}
