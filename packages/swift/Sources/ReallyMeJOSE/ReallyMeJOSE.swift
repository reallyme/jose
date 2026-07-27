// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeJOSEProto
import SwiftProtobuf

/// Typed Swift facade over the canonical Rust JOSE operation contract.
public struct ReallyMeJOSE: Sendable {
  private let provider: any ReallyMeJOSENativeProvider

  public init(nativeLibrary: ReallyMeJOSENativeLibrary) throws {
    provider = try ReallyMeJOSERustProvider(library: nativeLibrary)
  }

  #if REALLYME_JOSE_LINKED_FFI
    public init() throws {
      provider = try ReallyMeJOSERustProvider()
    }
  #endif

  public func signJWS(
    algorithm: ReallyMeJOSESignatureAlgorithm,
    privateKey: [UInt8],
    payload: [UInt8]
  ) throws -> String {
    try requireAggregateInput([privateKey.count, payload.count])
    var operation = ReallyMeProtoJoseJwsSignRequest()
    operation.algorithm = protoSignatureAlgorithm(algorithm)
    operation.privateKey = Data(privateKey)
    operation.payload = Data(payload)
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwsSign(operation)
    var response = try execute(&request)
    guard case .jwsSign(let selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    switch selected.outcome {
    case .result(let result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      response.response = nil
      return result.compact
    case .error(let error):
      throw try sdkError(error)
    case nil:
      throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func verifyJWS(
    algorithm: ReallyMeJOSESignatureAlgorithm,
    compact: String,
    publicKey: [UInt8]
  ) throws {
    try requireAggregateInput([compact.utf8.count, publicKey.count])
    var operation = ReallyMeProtoJoseJwsVerifyRequest()
    operation.algorithm = protoSignatureAlgorithm(algorithm)
    operation.compact = compact
    operation.publicKey = Data(publicKey)
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwsVerify(operation)
    let response = try execute(&request)
    guard case .jwsVerify(let selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    switch selected.outcome {
    case .result(let result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
    case .error(let error):
      throw try sdkError(error)
    case nil:
      throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func encodeUnsignedJWT(claimsJSON: [UInt8]) throws -> String {
    try requireAggregateInput([claimsJSON.count])
    var operation = ReallyMeProtoJoseJwtEncodeUnsignedRequest()
    operation.claimsJson = Data(claimsJSON)
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwtEncodeUnsigned(operation)
    let response = try execute(&request)
    guard case .jwtEncodeUnsigned(let selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    switch selected.outcome {
    case .result(let result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      return result.compact
    case .error(let error): throw try sdkError(error)
    case nil: throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func decodeUnsignedJWT(_ compact: String) throws -> [UInt8] {
    try requireAggregateInput([compact.utf8.count])
    var operation = ReallyMeProtoJoseJwtDecodeUnsignedRequest()
    operation.compact = compact
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwtDecodeUnsigned(operation)
    var response = try execute(&request)
    guard case .jwtDecodeUnsigned(var selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    response.response = nil
    switch selected.outcome {
    case .result(var result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      selected.outcome = nil
      defer { ReallyMeJOSEMemory.clearOwned(&result.claimsJson) }
      return [UInt8](result.claimsJson)
    case .error(let error): throw try sdkError(error)
    case nil: throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func signJWT(
    claimsJSON: [UInt8],
    jwkJSON: [UInt8],
    privateKey: [UInt8],
    type: String = ""
  ) throws -> String {
    try requireAggregateInput([claimsJSON.count, jwkJSON.count, privateKey.count, type.utf8.count])
    var operation = ReallyMeProtoJoseJwtSignRequest()
    operation.claimsJson = Data(claimsJSON)
    operation.jwkJson = Data(jwkJSON)
    operation.privateKey = Data(privateKey)
    operation.typ = type
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwtSign(operation)
    let response = try execute(&request)
    guard case .jwtSign(let selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    switch selected.outcome {
    case .result(let result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      return result.compact
    case .error(let error): throw try sdkError(error)
    case nil: throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func verifyJWT(
    compact: String,
    jwkJSON: [UInt8],
    publicKey: [UInt8],
    headerPolicy: ReallyMeJOSEJWTHeaderPolicy? = nil,
    temporalPolicy: ReallyMeJOSEJWTTemporalPolicy? = nil,
    signatureOnly: Bool = false
  ) throws -> [UInt8] {
    try requireAggregateInput([compact.utf8.count, jwkJSON.count, publicKey.count])
    var operation = ReallyMeProtoJoseJwtVerifyRequest()
    operation.compact = compact
    operation.jwkJson = Data(jwkJSON)
    operation.publicKey = Data(publicKey)
    operation.signatureOnly = signatureOnly
    if let headerPolicy { operation.headerPolicy = protoJWTHeaderPolicy(headerPolicy) }
    if let temporalPolicy { operation.temporalPolicy = protoJWTTemporalPolicy(temporalPolicy) }
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwtVerify(operation)
    var response = try execute(&request)
    guard case .jwtVerify(var selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    response.response = nil
    switch selected.outcome {
    case .result(var result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      selected.outcome = nil
      defer { ReallyMeJOSEMemory.clearOwned(&result.claimsJson) }
      return [UInt8](result.claimsJson)
    case .error(let error): throw try sdkError(error)
    case nil: throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func encryptJWE(
    keyManagementAlgorithm: ReallyMeJOSEJWEKeyManagementAlgorithm,
    contentEncryptionAlgorithm: ReallyMeJOSEJWEContentEncryptionAlgorithm,
    key: [UInt8],
    plaintext: [UInt8],
    keyIdentifier: String = "",
    agreementPartyUInfo: [UInt8] = [],
    agreementPartyVInfo: [UInt8] = [],
    type: String = "",
    contentType: String = ""
  ) throws -> String {
    try requireAggregateInput([
      key.count, plaintext.count, keyIdentifier.utf8.count,
      agreementPartyUInfo.count, agreementPartyVInfo.count,
      type.utf8.count, contentType.utf8.count,
    ])
    var operation = ReallyMeProtoJoseJweEncryptRequest()
    operation.keyManagementAlgorithm = protoKeyManagementAlgorithm(keyManagementAlgorithm)
    operation.contentEncryptionAlgorithm = protoContentEncryptionAlgorithm(
      contentEncryptionAlgorithm)
    operation.key = Data(key)
    operation.plaintext = Data(plaintext)
    operation.kid = keyIdentifier
    operation.apu = Data(agreementPartyUInfo)
    operation.apv = Data(agreementPartyVInfo)
    operation.typ = type
    operation.cty = contentType
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jweEncrypt(operation)
    let response = try execute(&request)
    guard case .jweEncrypt(let selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    switch selected.outcome {
    case .result(let result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      return result.compact
    case .error(let error): throw try sdkError(error)
    case nil: throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  public func decryptJWE(
    compact: String,
    keyManagementAlgorithm: ReallyMeJOSEJWEKeyManagementAlgorithm,
    contentEncryptionAlgorithm: ReallyMeJOSEJWEContentEncryptionAlgorithm,
    key: [UInt8],
    headerPolicy: ReallyMeJOSEJWEHeaderPolicy? = nil
  ) throws -> [UInt8] {
    try requireAggregateInput([compact.utf8.count, key.count])
    var operation = ReallyMeProtoJoseJweDecryptRequest()
    operation.compact = compact
    operation.keyManagementAlgorithm = protoKeyManagementAlgorithm(keyManagementAlgorithm)
    operation.contentEncryptionAlgorithm = protoContentEncryptionAlgorithm(
      contentEncryptionAlgorithm)
    operation.key = Data(key)
    if let headerPolicy { operation.headerPolicy = protoJWEHeaderPolicy(headerPolicy) }
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jweDecrypt(operation)
    var response = try execute(&request)
    guard case .jweDecrypt(var selected)? = response.response,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    response.response = nil
    switch selected.outcome {
    case .result(var result):
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      selected.outcome = nil
      defer { ReallyMeJOSEMemory.clearOwned(&result.plaintext) }
      return [UInt8](result.plaintext)
    case .error(let error): throw try sdkError(error)
    case nil: throw ReallyMeJOSEError.malformedProviderResponse
    }
  }

  /// Explicit wire-level API. The caller owns and must clear returned bytes.
  public func executeWireRequest(_ request: [UInt8]) throws -> [UInt8] {
    try provider.executeBinary(request)
  }

  /// Explicit generated-ProtoJSON request API returning canonical binary response bytes.
  public func executeWireJSONRequest(_ request: [UInt8]) throws -> [UInt8] {
    try provider.executeJSON(request)
  }

  private func execute(
    _ request: inout ReallyMeProtoJoseOperationRequest
  ) throws -> ReallyMeProtoJoseOperationResponse {
    defer { wipeRequest(&request) }
    var requestBytes: [UInt8]
    do {
      requestBytes = try request.serializedBytes()
    } catch {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    defer { provider.clearOwned(&requestBytes) }
    var responseBytes = try provider.executeBinary(requestBytes)
    defer { provider.clearOwned(&responseBytes) }
    let response: ReallyMeProtoJoseOperationResponse
    do {
      var options = BinaryDecodingOptions()
      options.messageDepthLimit = 32
      response = try ReallyMeProtoJoseOperationResponse(
        serializedBytes: responseBytes,
        options: options
      )
    } catch {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    guard response.contractVersion == .v1,
      response.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    if case .boundaryError(let error)? = response.response {
      throw try sdkError(error)
    }
    return response
  }

  private func requireAggregateInput(_ lengths: [Int]) throws {
    var aggregate = 0
    for length in lengths {
      let (sum, overflow) = aggregate.addingReportingOverflow(length)
      guard !overflow, sum <= provider.maximumBinaryRequestBytes else {
        throw ReallyMeJOSEError.jose(
          branch: .primitive,
          reason: .commonResourceLimitExceeded
        )
      }
      aggregate = sum
    }
  }
}

private func sdkError(_ error: ReallyMeProtoJoseError) throws -> ReallyMeJOSEError {
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
  return .jose(branch: branch, reason: reason)
}

private func protoSignatureAlgorithm(
  _ value: ReallyMeJOSESignatureAlgorithm
) -> ReallyMeProtoJoseSignatureAlgorithm {
  switch value {
  case .edDSA: .eddsa
  case .es256: .es256
  }
}

private func protoKeyManagementAlgorithm(
  _ value: ReallyMeJOSEJWEKeyManagementAlgorithm
) -> ReallyMeProtoJoseJweKeyManagementAlgorithm {
  switch value {
  case .direct: .direct
  case .ecdhESP256: .ecdhEsP256
  case .ecdhESP384: .ecdhEsP384
  case .ecdhESP521: .ecdhEsP521
  }
}

private func protoContentEncryptionAlgorithm(
  _ value: ReallyMeJOSEJWEContentEncryptionAlgorithm
) -> ReallyMeProtoJoseJweContentEncryptionAlgorithm {
  switch value {
  case .a128GCM: .a128Gcm
  case .a192GCM: .a192Gcm
  case .a256GCM: .a256Gcm
  }
}

private func protoJWTHeaderPolicy(
  _ value: ReallyMeJOSEJWTHeaderPolicy
) -> ReallyMeProtoJoseJwtHeaderValidationPolicy {
  var result = ReallyMeProtoJoseJwtHeaderValidationPolicy()
  result.allowMissingTyp = value.allowMissingTyp
  result.allowEmbeddedKeyHeader = value.allowEmbeddedKeyHeader
  result.acceptedTypValues = value.acceptedTypValues
  return result
}

private func protoJWTTemporalPolicy(
  _ value: ReallyMeJOSEJWTTemporalPolicy
) -> ReallyMeProtoJoseJwtTemporalValidationPolicy {
  var result = ReallyMeProtoJoseJwtTemporalValidationPolicy()
  result.requireExp = value.requireExpiration
  result.requireNbf = value.requireNotBefore
  result.requireIat = value.requireIssuedAt
  result.clockSkewSeconds = value.clockSkewSeconds
  result.maxFutureIatSkewSeconds = value.maximumFutureIssuedAtSkewSeconds
  result.nowUnix = value.nowUnix
  result.expectedAudience = value.expectedAudience
  result.expectedIssuer = value.expectedIssuer ?? ""
  result.expectedSubject = value.expectedSubject ?? ""
  return result
}

private func protoJWEHeaderPolicy(
  _ value: ReallyMeJOSEJWEHeaderPolicy
) -> ReallyMeProtoJoseJweHeaderValidationPolicy {
  var result = ReallyMeProtoJoseJweHeaderValidationPolicy()
  result.requireKid = value.requireKeyIdentifier
  if let expected = value.expectedKeyIdentifier {
    var wrapped = ReallyMeProtoJoseExpectedString()
    wrapped.value = expected
    result.expectedKid = wrapped
  }
  if let expected = value.expectedType {
    var wrapped = ReallyMeProtoJoseExpectedString()
    wrapped.value = expected
    result.expectedTyp = wrapped
  }
  if let expected = value.expectedContentType {
    var wrapped = ReallyMeProtoJoseExpectedString()
    wrapped.value = expected
    result.expectedCty = wrapped
  }
  if let expected = value.expectedAgreementPartyUInfo {
    var wrapped = ReallyMeProtoJoseExpectedBytes()
    wrapped.value = Data(expected)
    result.expectedApu = wrapped
  }
  if let expected = value.expectedAgreementPartyVInfo {
    var wrapped = ReallyMeProtoJoseExpectedBytes()
    wrapped.value = Data(expected)
    result.expectedApv = wrapped
  }
  return result
}

private func wipeRequest(_ request: inout ReallyMeProtoJoseOperationRequest) {
  switch request.operation {
  case .jwsSign:
    ReallyMeJOSEMemory.clearOwned(&request.jwsSign.privateKey)
    ReallyMeJOSEMemory.clearOwned(&request.jwsSign.payload)
  case .jwsVerify:
    ReallyMeJOSEMemory.clearOwned(&request.jwsVerify.publicKey)
  case .jwtEncodeUnsigned:
    ReallyMeJOSEMemory.clearOwned(&request.jwtEncodeUnsigned.claimsJson)
  case .jwtDecodeUnsigned:
    break
  case .jwtSign:
    ReallyMeJOSEMemory.clearOwned(&request.jwtSign.claimsJson)
    ReallyMeJOSEMemory.clearOwned(&request.jwtSign.jwkJson)
    ReallyMeJOSEMemory.clearOwned(&request.jwtSign.privateKey)
  case .jwtVerify:
    ReallyMeJOSEMemory.clearOwned(&request.jwtVerify.jwkJson)
    ReallyMeJOSEMemory.clearOwned(&request.jwtVerify.publicKey)
  case .jweEncrypt:
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.key)
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.plaintext)
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.apu)
    ReallyMeJOSEMemory.clearOwned(&request.jweEncrypt.apv)
  case .jweDecrypt:
    ReallyMeJOSEMemory.clearOwned(&request.jweDecrypt.key)
  case nil:
    break
  }
  request.operation = nil
}
