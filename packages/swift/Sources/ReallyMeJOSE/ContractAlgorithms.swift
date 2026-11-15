// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import ReallyMeJOSEProto

public enum ReallyMeJOSEErrorBranch: Sendable, Equatable, CaseIterable {
  case primitive
  case provider
  case backend

  public init(contract: ReallyMeProtoJoseErrorBranch) throws(ReallyMeJOSEError) {
    switch contract {
    case .primitive: self = .primitive
    case .provider: self = .provider
    case .backend: self = .backend
    default: throw .jose(branch: .provider, reason: .providerUnsupported)
    }
  }
}

func protoErrorBranch(
  _ value: ReallyMeJOSEErrorBranch
) -> ReallyMeProtoJoseErrorBranch {
  switch value {
  case .primitive: .primitive
  case .provider: .provider
  case .backend: .backend
  }
}

public enum ReallyMeJOSESignatureAlgorithm: Sendable, Equatable, CaseIterable {
  case edDSA
  case es256
  case es256k

  public init(contract: ReallyMeProtoJoseSignatureAlgorithm) throws(ReallyMeJOSEError) {
    switch contract {
    case .eddsa: self = .edDSA
    case .es256: self = .es256
    case .es256K: self = .es256k
    default: throw .jose(branch: .provider, reason: .providerUnsupported)
    }
  }
}

func protoSignatureAlgorithm(
  _ value: ReallyMeJOSESignatureAlgorithm
) -> ReallyMeProtoJoseSignatureAlgorithm {
  switch value {
  case .edDSA: .eddsa
  case .es256: .es256
  case .es256k: .es256K
  }
}

public enum ReallyMeJOSEJWEKeyManagementAlgorithm: Sendable, Equatable, CaseIterable {
  case direct
  case ecdhESP256
  case ecdhESP384
  case ecdhESP521

  public init(contract: ReallyMeProtoJoseJweKeyManagementAlgorithm) throws(ReallyMeJOSEError) {
    switch contract {
    case .direct: self = .direct
    case .ecdhEsP256: self = .ecdhESP256
    case .ecdhEsP384: self = .ecdhESP384
    case .ecdhEsP521: self = .ecdhESP521
    default: throw .jose(branch: .provider, reason: .providerUnsupported)
    }
  }
}

func protoKeyManagementAlgorithm(
  _ value: ReallyMeJOSEJWEKeyManagementAlgorithm
) -> ReallyMeProtoJoseJweKeyManagementAlgorithm {
  switch value {
  case .direct: .direct
  case .ecdhESP256: .ecdhEsP256
  case .ecdhESP384: .ecdhEsP384
  case .ecdhESP521: .ecdhEsP521
  }
}

public enum ReallyMeJOSEJWEContentEncryptionAlgorithm: Sendable, Equatable, CaseIterable {
  case a128GCM
  case a192GCM
  case a256GCM

  public init(contract: ReallyMeProtoJoseJweContentEncryptionAlgorithm) throws(ReallyMeJOSEError) {
    switch contract {
    case .a128Gcm: self = .a128GCM
    case .a192Gcm: self = .a192GCM
    case .a256Gcm: self = .a256GCM
    default: throw .jose(branch: .provider, reason: .providerUnsupported)
    }
  }
}

func protoContentEncryptionAlgorithm(
  _ value: ReallyMeJOSEJWEContentEncryptionAlgorithm
) -> ReallyMeProtoJoseJweContentEncryptionAlgorithm {
  switch value {
  case .a128GCM: .a128Gcm
  case .a192GCM: .a192Gcm
  case .a256GCM: .a256Gcm
  }
}

public enum ReallyMeJOSEJWECompressionAlgorithm: Sendable, Equatable, CaseIterable {
  case deflate

  public init(contract: ReallyMeProtoJoseJweCompressionAlgorithm) throws(ReallyMeJOSEError) {
    switch contract {
    case .deflate: self = .deflate
    default: throw .jose(branch: .provider, reason: .providerUnsupported)
    }
  }
}

func protoCompressionAlgorithm(
  _ value: ReallyMeJOSEJWECompressionAlgorithm
) -> ReallyMeProtoJoseJweCompressionAlgorithm {
  switch value {
  case .deflate: .deflate
  }
}
