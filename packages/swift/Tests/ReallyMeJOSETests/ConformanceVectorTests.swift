// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeJOSEProto
import SwiftProtobuf
import Testing

@testable import ReallyMeJOSE

private enum VectorFixtureError: Error {
  case invalidFixture
}

@Test func completeJWSVectorCorpusPreservesTypedResults() throws {
  let jose = try configuredVectorJOSE()
  for vector in try vectorCases(named: "jws-compact.json") {
    try runJWSVector(vector, jose: jose)
  }
}

@Test func completeJWTVectorCorporaPreserveClaimsAndTypedFailures() throws {
  let jose = try configuredVectorJOSE()
  for vector in try vectorCases(named: "signed-jwt.json") {
    try runSignedJWTVector(vector, jose: jose)
  }
  for vector in try vectorCases(named: "unsigned-jwt.json") {
    try runUnsignedJWTVector(vector, jose: jose)
  }
}

@Test func completeJWEVectorCorpusPreservesPlaintextAndTypedFailures() throws {
  let jose = try configuredVectorJOSE()
  for vector in try vectorCases(named: "jwe-compact.json") {
    try runJWEVector(vector, jose: jose)
  }
}

@Test func panvaInteropCorpusUsesTheSameTypedFacade() throws {
  let jose = try configuredVectorJOSE()
  for vector in try vectorCases(named: "panva-jose.json") {
    switch try requiredString(vector, "format") {
    case "jws-compact": try runJWSVector(vector, jose: jose)
    case "signed-jwt", "jwt-compact": try runSignedJWTVector(vector, jose: jose)
    case "jwe-compact": try runJWEVector(vector, jose: jose)
    default: throw VectorFixtureError.invalidFixture
    }
  }
}

@Test func binaryAndProtoJSONWireRoutesAreByteIdentical() throws {
  let jose = try configuredVectorJOSE()
  let vector = try #require(vectorCases(named: "unsigned-jwt.json").first)
  let compact = try requiredString(vector, "compact")
  var operation = ReallyMeProtoJoseJwtDecodeUnsignedRequest()
  operation.compact = compact
  var request = ReallyMeProtoJoseOperationRequest()
  request.operation = .jwtDecodeUnsigned(operation)
  var binary: [UInt8] = try request.serializedBytes()
  var json = Array(#"{"jwtDecodeUnsigned":{"compact":"\#(compact)"}}"#.utf8)
  var binaryResponse = try jose.executeWireRequest(binary)
  var jsonResponse = try jose.executeWireJSONRequest(json)
  defer {
    clearVectorBytes(&binary)
    clearVectorBytes(&json)
    clearVectorBytes(&binaryResponse)
    clearVectorBytes(&jsonResponse)
  }
  #expect(binaryResponse == jsonResponse)
}

@Test func hostileWireInputsAndProviderSelectionPreserveExactErrors() throws {
  let jose = try configuredVectorJOSE()
  var malformedBinary: [UInt8] = [0xff]
  var malformedJSON = Array(#"{"jwtDecodeUnsigned":"#.utf8)
  var binaryResponse = try jose.executeWireRequest(malformedBinary)
  var jsonResponse = try jose.executeWireJSONRequest(malformedJSON)
  defer {
    clearVectorBytes(&malformedBinary)
    clearVectorBytes(&malformedJSON)
    clearVectorBytes(&binaryResponse)
    clearVectorBytes(&jsonResponse)
  }
  let binaryEnvelope = try ReallyMeProtoJoseOperationResponse(
    serializedBytes: Data(binaryResponse))
  let jsonEnvelope = try ReallyMeProtoJoseOperationResponse(serializedBytes: Data(jsonResponse))
  guard case .boundaryError(let binaryError)? = binaryEnvelope.response,
    case .boundaryError(let jsonError)? = jsonEnvelope.response
  else {
    throw VectorFixtureError.invalidFixture
  }
  try requireGeneratedError(binaryError, branch: .primitive, reason: .commonMalformedProtobuf)
  try requireGeneratedError(jsonError, branch: .primitive, reason: .commonMalformedJson)

  var verify = ReallyMeProtoJoseJwsVerifyRequest()
  verify.algorithm = .UNRECOGNIZED(999)
  var request = ReallyMeProtoJoseOperationRequest()
  request.operation = .jwsVerify(verify)
  var requestBytes: [UInt8] = try request.serializedBytes()
  var responseBytes = try jose.executeWireRequest(requestBytes)
  defer {
    clearVectorBytes(&requestBytes)
    clearVectorBytes(&responseBytes)
  }
  let response = try ReallyMeProtoJoseOperationResponse(serializedBytes: Data(responseBytes))
  guard case .jwsVerify(let selected)? = response.response,
    case .error(let error)? = selected.outcome
  else {
    throw VectorFixtureError.invalidFixture
  }
  try requireGeneratedError(error, branch: .provider, reason: .providerUnsupported)
}

@Test func temporalWirePolicyRequiresExplicitVerificationTime() throws {
  let jose = try configuredVectorJOSE()
  let vector = try #require(vectorCases(named: "signed-jwt.json").first)
  var publicKey = try vectorBytes(hex: requiredString(vector, "public_key_hex"))
  var jwk = try canonicalJSONData(requiredObject(vector, "verification_jwk")).map { $0 }
  var temporal = ReallyMeProtoJoseJwtTemporalValidationPolicy()
  temporal.requireExp = true
  var verify = ReallyMeProtoJoseJwtVerifyRequest()
  verify.compact = try requiredString(vector, "compact")
  verify.jwkJson = Data(jwk)
  verify.publicKey = Data(publicKey)
  verify.temporalPolicy = temporal
  var request = ReallyMeProtoJoseOperationRequest()
  request.operation = .jwtVerify(verify)
  var requestBytes: [UInt8] = try request.serializedBytes()
  var responseBytes = try jose.executeWireRequest(requestBytes)
  defer {
    clearVectorBytes(&publicKey)
    clearVectorBytes(&jwk)
    clearVectorBytes(&requestBytes)
    clearVectorBytes(&responseBytes)
  }
  let response = try ReallyMeProtoJoseOperationResponse(serializedBytes: Data(responseBytes))
  guard case .jwtVerify(let selected)? = response.response,
    case .error(let error)? = selected.outcome
  else {
    throw VectorFixtureError.invalidFixture
  }
  try requireGeneratedError(error, branch: .primitive, reason: .jwtInvalidVerificationTime)
}

private enum GeneratedErrorBranch {
  case primitive
  case provider
  case backend
}

private func requireGeneratedError(
  _ error: ReallyMeProtoJoseError,
  branch: GeneratedErrorBranch,
  reason: ReallyMeProtoJoseErrorReason
) throws {
  switch (branch, error.error) {
  case (.primitive, .primitive(let selected)?): #expect(selected.reason == reason)
  case (.provider, .provider(let selected)?): #expect(selected.reason == reason)
  case (.backend, .backend(let selected)?): #expect(selected.reason == reason)
  default: throw VectorFixtureError.invalidFixture
  }
}

private func configuredVectorJOSE() throws -> ReallyMeJOSE {
  try ReallyMeJOSE(nativeLibrary: ReallyMeJOSENativeLibrary(path: try vectorNativeLibraryPath()))
}

private func vectorNativeLibraryPath() throws -> String {
  if let configured = ProcessInfo.processInfo.environment["REALLYME_JOSE_FFI_LIBRARY_PATH"],
    !configured.isEmpty
  {
    return configured
  }
  let candidate = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    .appendingPathComponent("target/debug/libreallyme_jose_ffi.dylib").path
  guard FileManager.default.fileExists(atPath: candidate) else {
    throw ReallyMeJOSEError.nativeLibraryNotFound
  }
  return candidate
}

private func runJWSVector(_ vector: [String: Any], jose: ReallyMeJOSE) throws {
  let algorithm: ReallyMeJOSESignatureAlgorithm
  switch try requiredString(vector, "alg") {
  case "EdDSA": algorithm = .edDSA
  case "ES256": algorithm = .es256
  default: throw VectorFixtureError.invalidFixture
  }
  var publicKey = try vectorBytes(hex: requiredString(vector, "public_key_hex"))
  defer { clearVectorBytes(&publicKey) }
  let compact = try requiredString(vector, "compact")
  if optionalBool(vector, "expected_valid") == true {
    try jose.verifyJWS(algorithm: algorithm, compact: compact, publicKey: publicKey)
  } else {
    let expected = try expectedJWSError(requiredString(vector, "expected_error"))
    expectVectorFailure(expected) {
      try jose.verifyJWS(algorithm: algorithm, compact: compact, publicKey: publicKey)
    }
  }
}

private func runSignedJWTVector(_ vector: [String: Any], jose: ReallyMeJOSE) throws {
  var publicKey = try vectorBytes(hex: requiredString(vector, "public_key_hex"))
  var jwk = try canonicalJSONData(requiredObject(vector, "verification_jwk")).map { $0 }
  defer {
    clearVectorBytes(&publicKey)
    clearVectorBytes(&jwk)
  }
  let temporalPolicy: ReallyMeJOSEJWTTemporalPolicy?
  if let now = optionalUInt64(vector, "now_unix") {
    guard optionalString(vector, "temporal_policy") ?? "strict" == "strict" else {
      throw VectorFixtureError.invalidFixture
    }
    temporalPolicy = ReallyMeJOSEJWTTemporalPolicy(
      requireExpiration: true,
      requireNotBefore: false,
      requireIssuedAt: false,
      clockSkewSeconds: 60,
      maximumFutureIssuedAtSkewSeconds: 60,
      nowUnix: now,
      expectedAudience: "did:me:verifier"
    )
  } else {
    temporalPolicy = nil
  }
  let compact = try requiredString(vector, "compact")
  if let expectedClaims = optionalObject(vector, "expected_claims_json") {
    var actual = try jose.verifyJWT(
      compact: compact,
      jwkJSON: jwk,
      publicKey: publicKey,
      temporalPolicy: temporalPolicy,
      signatureOnly: temporalPolicy == nil
    )
    defer { clearVectorBytes(&actual) }
    #expect(try canonicalJSONData(from: actual) == canonicalJSONData(expectedClaims))
  } else {
    let expected = try expectedJWTError(requiredString(vector, "expected_error"))
    expectVectorFailure(expected) {
      var output = try jose.verifyJWT(
        compact: compact,
        jwkJSON: jwk,
        publicKey: publicKey,
        temporalPolicy: temporalPolicy,
        signatureOnly: temporalPolicy == nil
      )
      clearVectorBytes(&output)
    }
  }
}

private func runUnsignedJWTVector(_ vector: [String: Any], jose: ReallyMeJOSE) throws {
  let compact = try requiredString(vector, "compact")
  if let expectedClaims = optionalObject(vector, "expected_claims_json") {
    var actual = try jose.decodeUnsignedJWT(compact)
    defer { clearVectorBytes(&actual) }
    #expect(try canonicalJSONData(from: actual) == canonicalJSONData(expectedClaims))
  } else {
    let expected = try expectedJWTError(requiredString(vector, "expected_error"))
    expectVectorFailure(expected) {
      var output = try jose.decodeUnsignedJWT(compact)
      clearVectorBytes(&output)
    }
  }
}

private func runJWEVector(_ vector: [String: Any], jose: ReallyMeJOSE) throws {
  let keyHex = optionalString(vector, "recipient_private_key_hex")
    ?? optionalString(vector, "cek_hex")
  guard let keyHex else { throw VectorFixtureError.invalidFixture }
  var key = try vectorBytes(hex: keyHex)
  defer { clearVectorBytes(&key) }

  let keyManagement: ReallyMeJOSEJWEKeyManagementAlgorithm
  if try requiredString(vector, "alg") == "ECDH-ES" {
    switch key.count {
    case 32: keyManagement = .ecdhESP256
    case 48: keyManagement = .ecdhESP384
    case 66: keyManagement = .ecdhESP521
    default: throw VectorFixtureError.invalidFixture
    }
  } else {
    keyManagement = .direct
  }
  let contentEncryption: ReallyMeJOSEJWEContentEncryptionAlgorithm
  switch try requiredString(vector, "enc") {
  case "A192GCM": contentEncryption = .a192GCM
  case "A256GCM": contentEncryption = .a256GCM
  default: contentEncryption = .a128GCM
  }
  let compact = try requiredString(vector, "compact")
  if let expectedPlaintext = optionalObject(vector, "expected_plaintext_json") {
    var actual = try jose.decryptJWE(
      compact: compact,
      keyManagementAlgorithm: keyManagement,
      contentEncryptionAlgorithm: contentEncryption,
      key: key
    )
    defer { clearVectorBytes(&actual) }
    #expect(try canonicalJSONData(from: actual) == canonicalJSONData(expectedPlaintext))
  } else {
    let expected = try expectedJWEError(requiredString(vector, "expected_error"))
    expectVectorFailure(expected) {
      var output = try jose.decryptJWE(
        compact: compact,
        keyManagementAlgorithm: keyManagement,
        contentEncryptionAlgorithm: contentEncryption,
        key: key
      )
      clearVectorBytes(&output)
    }
  }
}

private func expectVectorFailure(
  _ reason: ReallyMeJOSEErrorReason,
  operation: () throws -> Void
) {
  do {
    try operation()
    Issue.record("expected typed JOSE vector failure")
  } catch let failure as ReallyMeJOSEError {
    #expect(failure == .jose(branch: .primitive, reason: reason))
  } catch {
    Issue.record("unexpected vector failure type")
  }
}

private func expectedJWSError(_ name: String) throws -> ReallyMeJOSEErrorReason {
  switch name {
  case "InvalidCompactEncoding": return .jwsInvalidCompact
  case "HeaderMismatch": return .jwsHeaderMismatch
  case "BadSignatureBase64": return .jwsBadSignatureBase64
  case "InvalidSignature": return .jwsInvalidSignature
  default: throw VectorFixtureError.invalidFixture
  }
}

private func expectedJWTError(_ name: String) throws -> ReallyMeJOSEErrorReason {
  switch name.split(separator: ":", maxSplits: 1).first {
  case "InvalidJwtFormat": return .jwtInvalidCompact
  case "InvalidHeader": return .jwtInvalidHeader
  case "UnsupportedAlgorithm": return .jwtUnsupportedAlgorithm
  case "AlgorithmMismatch": return .jwtAlgorithmMismatch
  case "KeyIdMismatch": return .jwtKidPolicyMismatch
  case "InvalidSignature": return .jwtInvalidSignature
  case "MissingRequiredTemporalClaim": return .jwtMissingRequiredTemporalClaim
  case "InvalidTemporalClaimValue": return .jwtInvalidTemporalClaimValue
  case "Expired": return .jwtExpired
  case "NotYetValid": return .jwtNotYetValid
  case "IssuedAtInFuture": return .jwtIssuedAtInFuture
  default: throw VectorFixtureError.invalidFixture
  }
}

private func expectedJWEError(_ name: String) throws -> ReallyMeJOSEErrorReason {
  switch name {
  case "InvalidCompact": return .jweInvalidCompact
  case "InvalidEncoding": return .jweInvalidEncoding
  case "InvalidHeader": return .jweInvalidHeader
  case "UnsupportedKeyManagementAlgorithm": return .jweUnsupportedKeyManagementAlgorithm
  case "UnsupportedContentEncryptionAlgorithm": return .jweUnsupportedContentEncryptionAlgorithm
  case "MissingRequiredHeaderParameter": return .jweMissingRequiredHeaderParameter
  case "HeaderPolicyMismatch": return .jweHeaderPolicyMismatch
  case "InvalidEncryptedKey": return .jweInvalidEncryptedKey
  case "InvalidContentEncryptionKey": return .jweInvalidContentEncryptionKey
  case "InvalidContentCipherInput": return .jweInvalidContentCipherInput
  case "Decrypt": return .jweDecryptFailed
  case "Encrypt": return .jweEncryptFailed
  case "InvalidKeyAgreementKey": return .jweInvalidKeyAgreementKey
  case "InvalidPayloadJson": return .jweInvalidPayloadJson
  default: throw VectorFixtureError.invalidFixture
  }
}

private func vectorCases(named name: String) throws -> [[String: Any]] {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  let file = root.appendingPathComponent("vectors").appendingPathComponent(name)
  let data = try Data(contentsOf: file, options: .mappedIfSafe)
  guard let document = try JSONSerialization.jsonObject(with: data) as? [String: Any],
    let cases = document["cases"] as? [[String: Any]], !cases.isEmpty
  else {
    throw VectorFixtureError.invalidFixture
  }
  return cases
}

private func requiredString(_ object: [String: Any], _ field: String) throws -> String {
  guard let value = object[field] as? String else { throw VectorFixtureError.invalidFixture }
  return value
}

private func optionalString(_ object: [String: Any], _ field: String) -> String? {
  object[field] as? String
}

private func optionalBool(_ object: [String: Any], _ field: String) -> Bool? {
  object[field] as? Bool
}

private func optionalUInt64(_ object: [String: Any], _ field: String) -> UInt64? {
  guard let number = object[field] as? NSNumber, number.int64Value >= 0 else { return nil }
  return number.uint64Value
}

private func requiredObject(_ object: [String: Any], _ field: String) throws -> [String: Any] {
  guard let value = object[field] as? [String: Any] else {
    throw VectorFixtureError.invalidFixture
  }
  return value
}

private func optionalObject(_ object: [String: Any], _ field: String) -> [String: Any]? {
  object[field] as? [String: Any]
}

private func vectorBytes(hex: String) throws -> [UInt8] {
  guard hex.utf8.count.isMultiple(of: 2) else { throw VectorFixtureError.invalidFixture }
  var output: [UInt8] = []
  output.reserveCapacity(hex.utf8.count / 2)
  var index = hex.startIndex
  while index < hex.endIndex {
    let next = hex.index(index, offsetBy: 2)
    guard let value = UInt8(hex[index..<next], radix: 16) else {
      clearVectorBytes(&output)
      throw VectorFixtureError.invalidFixture
    }
    output.append(value)
    index = next
  }
  return output
}

private func canonicalJSONData(from bytes: [UInt8]) throws -> Data {
  let value = try JSONSerialization.jsonObject(with: Data(bytes), options: .fragmentsAllowed)
  return try canonicalJSONData(value)
}

private func canonicalJSONData(_ value: Any) throws -> Data {
  guard JSONSerialization.isValidJSONObject(value) else {
    throw VectorFixtureError.invalidFixture
  }
  return try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
}

private func clearVectorBytes(_ bytes: inout [UInt8]) {
  bytes.withUnsafeMutableBufferPointer { buffer in
    buffer.initialize(repeating: 0)
  }
}
