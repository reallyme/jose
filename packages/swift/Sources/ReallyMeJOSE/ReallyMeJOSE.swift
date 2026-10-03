// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeJOSEProto
import SwiftProtobuf

/// Typed Swift facade over the canonical Rust JOSE operation contract.
public struct ReallyMeJOSE: Sendable {
  private let provider: any ReallyMeJOSENativeProvider

  public init(nativeLibrary: ReallyMeJOSENativeLibrary) throws(ReallyMeJOSEError) {
    provider = try ReallyMeJOSERustProvider(library: nativeLibrary)
  }

  #if REALLYME_JOSE_LINKED_FFI
    public init() throws(ReallyMeJOSEError) {
      provider = try ReallyMeJOSERustProvider()
    }
  #endif

  public func signJWS(
    algorithm: ReallyMeJOSESignatureAlgorithm,
    privateKey: [UInt8],
    payload: [UInt8]
  ) throws(ReallyMeJOSEError) -> String {
    try requireAggregateInput([privateKey.count, payload.count])
    var operation = ReallyMeProtoJoseJwsSignRequest()
    operation.algorithm = protoSignatureAlgorithm(algorithm)
    operation.privateKey = ReallyMeJOSEMemory.ownedData(privateKey)
    operation.payload = ReallyMeJOSEMemory.ownedData(payload)
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
  ) throws(ReallyMeJOSEError) {
    try requireAggregateInput([compact.utf8.count, publicKey.count])
    var operation = ReallyMeProtoJoseJwsVerifyRequest()
    operation.algorithm = protoSignatureAlgorithm(algorithm)
    operation.compact = compact
    operation.publicKey = ReallyMeJOSEMemory.ownedData(publicKey)
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwsVerify(operation)
    var response = try execute(&request)
    var responseCase = ReallyMeJOSEMemory.take(&response.response)
    guard case .jwsVerify(var selected)? = responseCase,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    responseCase = nil
    var outcome = ReallyMeJOSEMemory.take(&selected.outcome)
    if case .result? = outcome {
      guard case .result(var result)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      let resultIsClean = result.unknownFields.data.isEmpty
      ReallyMeJOSEMemory.clearOwned(&result.protectedHeaderJson)
      ReallyMeJOSEMemory.clearOwned(&result.payload)
      guard resultIsClean else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      return
    }
    if case .error? = outcome {
      guard case .error(let error)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      throw try sdkError(error)
    }
    throw ReallyMeJOSEError.malformedProviderResponse
  }

  public func encodeUnsignedJWT(claimsJSON: [UInt8]) throws(ReallyMeJOSEError) -> String {
    try requireAggregateInput([claimsJSON.count])
    var operation = ReallyMeProtoJoseJwtEncodeUnsignedRequest()
    operation.claimsJson = ReallyMeJOSEMemory.ownedData(claimsJSON)
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

  public func decodeUnsignedJWT(_ compact: String) throws(ReallyMeJOSEError) -> [UInt8] {
    try requireAggregateInput([compact.utf8.count])
    var operation = ReallyMeProtoJoseJwtDecodeUnsignedRequest()
    operation.compact = compact
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwtDecodeUnsigned(operation)
    var response = try execute(&request)
    var responseCase = ReallyMeJOSEMemory.take(&response.response)
    guard case .jwtDecodeUnsigned(var selected)? = responseCase,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    responseCase = nil
    var outcome = ReallyMeJOSEMemory.take(&selected.outcome)
    if case .result? = outcome {
      guard case .result(var result)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      defer { ReallyMeJOSEMemory.clearOwned(&result.claimsJson) }
      return [UInt8](result.claimsJson)
    }
    if case .error? = outcome {
      guard case .error(let error)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      throw try sdkError(error)
    }
    throw ReallyMeJOSEError.malformedProviderResponse
  }

  public func signJWT(
    claimsJSON: [UInt8],
    jwkJSON: [UInt8],
    privateKey: [UInt8],
    type: String = ""
  ) throws(ReallyMeJOSEError) -> String {
    try requireAggregateInput([claimsJSON.count, jwkJSON.count, privateKey.count, type.utf8.count])
    var operation = ReallyMeProtoJoseJwtSignRequest()
    operation.claimsJson = ReallyMeJOSEMemory.ownedData(claimsJSON)
    operation.jwkJson = ReallyMeJOSEMemory.ownedData(jwkJSON)
    operation.privateKey = ReallyMeJOSEMemory.ownedData(privateKey)
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
  ) throws(ReallyMeJOSEError) -> [UInt8] {
    try requireAggregateInput([compact.utf8.count, jwkJSON.count, publicKey.count])
    var operation = ReallyMeProtoJoseJwtVerifyRequest()
    operation.compact = compact
    operation.jwkJson = ReallyMeJOSEMemory.ownedData(jwkJSON)
    operation.publicKey = ReallyMeJOSEMemory.ownedData(publicKey)
    operation.signatureOnly = signatureOnly
    if let headerPolicy { operation.headerPolicy = protoJWTHeaderPolicy(headerPolicy) }
    if let temporalPolicy { operation.temporalPolicy = try protoJWTTemporalPolicy(temporalPolicy) }
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jwtVerify(operation)
    var response = try execute(&request)
    var responseCase = ReallyMeJOSEMemory.take(&response.response)
    guard case .jwtVerify(var selected)? = responseCase,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    responseCase = nil
    var outcome = ReallyMeJOSEMemory.take(&selected.outcome)
    if case .result? = outcome {
      guard case .result(var result)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      defer { ReallyMeJOSEMemory.clearOwned(&result.claimsJson) }
      return [UInt8](result.claimsJson)
    }
    if case .error? = outcome {
      guard case .error(let error)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      throw try sdkError(error)
    }
    throw ReallyMeJOSEError.malformedProviderResponse
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
    contentType: String = "",
    compressionAlgorithm: ReallyMeJOSEJWECompressionAlgorithm? = nil
  ) throws(ReallyMeJOSEError) -> String {
    try requireAggregateInput([
      key.count, plaintext.count, keyIdentifier.utf8.count,
      agreementPartyUInfo.count, agreementPartyVInfo.count,
      type.utf8.count, contentType.utf8.count,
    ])
    var operation = ReallyMeProtoJoseJweEncryptRequest()
    operation.keyManagementAlgorithm = protoKeyManagementAlgorithm(keyManagementAlgorithm)
    operation.contentEncryptionAlgorithm = protoContentEncryptionAlgorithm(
      contentEncryptionAlgorithm)
    operation.key = ReallyMeJOSEMemory.ownedData(key)
    operation.plaintext = ReallyMeJOSEMemory.ownedData(plaintext)
    operation.kid = keyIdentifier
    operation.apu = ReallyMeJOSEMemory.ownedData(agreementPartyUInfo)
    operation.apv = ReallyMeJOSEMemory.ownedData(agreementPartyVInfo)
    operation.typ = type
    operation.cty = contentType
    if let compressionAlgorithm {
      operation.compressionAlgorithm = protoCompressionAlgorithm(compressionAlgorithm)
    }
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
  ) throws(ReallyMeJOSEError) -> [UInt8] {
    try requireAggregateInput([compact.utf8.count, key.count])
    var operation = ReallyMeProtoJoseJweDecryptRequest()
    operation.compact = compact
    operation.keyManagementAlgorithm = protoKeyManagementAlgorithm(keyManagementAlgorithm)
    operation.contentEncryptionAlgorithm = protoContentEncryptionAlgorithm(
      contentEncryptionAlgorithm)
    operation.key = ReallyMeJOSEMemory.ownedData(key)
    if let headerPolicy { operation.headerPolicy = protoJWEHeaderPolicy(headerPolicy) }
    var request = ReallyMeProtoJoseOperationRequest()
    request.operation = .jweDecrypt(operation)
    var response = try execute(&request)
    var responseCase = ReallyMeJOSEMemory.take(&response.response)
    guard case .jweDecrypt(var selected)? = responseCase,
      selected.unknownFields.data.isEmpty
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    responseCase = nil
    var outcome = ReallyMeJOSEMemory.take(&selected.outcome)
    if case .result? = outcome {
      guard case .result(var result)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      guard result.unknownFields.data.isEmpty else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      defer { ReallyMeJOSEMemory.clearOwned(&result.plaintext) }
      return [UInt8](result.plaintext)
    }
    if case .error? = outcome {
      guard case .error(let error)? = ReallyMeJOSEMemory.take(&outcome) else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      throw try sdkError(error)
    }
    throw ReallyMeJOSEError.malformedProviderResponse
  }

  /// Explicit wire-level API. The caller owns and must clear returned bytes.
  public func executeWireRequest(_ request: [UInt8]) throws(ReallyMeJOSEError) -> [UInt8] {
    try provider.executeBinary(request)
  }

  /// Explicit generated-ProtoJSON request API returning canonical binary response bytes.
  public func executeWireJSONRequest(_ request: [UInt8]) throws(ReallyMeJOSEError) -> [UInt8] {
    try provider.executeJSON(request)
  }

  private func execute(
    _ request: inout ReallyMeProtoJoseOperationRequest
  ) throws(ReallyMeJOSEError) -> ReallyMeProtoJoseOperationResponse {
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

  private func requireAggregateInput(_ lengths: [Int]) throws(ReallyMeJOSEError) {
    var aggregate = 0
    for length in lengths {
      let (sum, overflow) = aggregate.addingReportingOverflow(length)
      guard overflow == false, sum <= provider.maximumBinaryRequestBytes else {
        throw ReallyMeJOSEError.jose(
          branch: .primitive,
          reason: .commonResourceLimitExceeded
        )
      }
      aggregate = sum
    }
  }
}
