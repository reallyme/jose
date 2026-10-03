// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeJOSEProto
import Testing

@testable import ReallyMeJOSE

private func nativeLibraryPath() throws -> String {
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

private func configuredJOSE() throws -> ReallyMeJOSE {
  try ReallyMeJOSE(nativeLibrary: ReallyMeJOSENativeLibrary(path: nativeLibraryPath()))
}

private func bytes(hex: String) throws -> [UInt8] {
  guard hex.utf8.count.isMultiple(of: 2) else {
    throw ReallyMeJOSEError.malformedProviderResponse
  }
  var result: [UInt8] = []
  result.reserveCapacity(hex.utf8.count / 2)
  var index = hex.startIndex
  while index < hex.endIndex {
    let next = hex.index(index, offsetBy: 2)
    guard let value = UInt8(hex[index..<next], radix: 16) else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    result.append(value)
    index = next
  }
  return result
}

@Test func memoryClearerZeroizesOwnedBuffers() {
  var array = [UInt8](repeating: 0xa5, count: 32)
  ReallyMeJOSEMemory.clearOwned(&array)
  #expect(array.allSatisfy { byte in byte == 0 })

  var data = Data(repeating: 0x5a, count: 32)
  ReallyMeJOSEMemory.clearOwned(&data)
  #expect(data.allSatisfy { byte in byte == 0 })
}

@Test func generatedMessageDebugAndReflectionRedactSensitiveFields() {
  var request = ReallyMeProtoJoseJwsSignRequest()
  request.privateKey = Data(repeating: 0xa5, count: 32)
  request.payload = Data("sensitive-payload".utf8)

  let debug = String(reflecting: request)
  var reflection = ""
  dump(request, to: &reflection)
  #expect(debug.contains("<redacted>"))
  #expect(reflection.contains("<redacted>"))
  #expect(!debug.contains("sensitive-payload"))
  #expect(!reflection.contains("sensitive-payload"))
  #expect(!reflection.contains("privateKey"))
}

@Test func policyDescriptionsAndReflectionRedactBoundIdentifiers() {
  let policy = ReallyMeJOSEJWTTemporalPolicy(
    requireExpiration: true,
    requireNotBefore: false,
    requireIssuedAt: false,
    clockSkewSeconds: 0,
    maximumFutureIssuedAtSkewSeconds: 0,
    nowUnix: 1,
    expectedAudience: "secret-audience",
    expectedIssuer: "secret-issuer",
    expectedSubject: "secret-subject"
  )
  let description = String(describing: policy)
  let debug = String(reflecting: policy)
  var reflection = ""
  dump(policy, to: &reflection)
  #expect(reflection.contains("<redacted>"))
  for output in [description, debug, reflection] {
    #expect(!output.contains("secret-audience"))
    #expect(!output.contains("secret-issuer"))
    #expect(!output.contains("secret-subject"))
  }
}

private final class WipeObservation: @unchecked Sendable {
  private let lock = NSLock()
  private var pointer: UInt = 0
  private var zeroed = false

  func record(_ bytes: UnsafeRawBufferPointer) {
    lock.lock()
    defer { lock.unlock() }
    pointer = bytes.baseAddress.map { UInt(bitPattern: $0) } ?? 0
    zeroed = bytes.allSatisfy { $0 == 0 }
  }

  func snapshot() -> (UInt, Bool) {
    lock.lock()
    defer { lock.unlock() }
    return (pointer, zeroed)
  }
}

@Test func ownedRequestDataWipesItsOriginalStorage() {
  let observation = WipeObservation()
  var data = ReallyMeJOSEMemory.ownedData(
    [UInt8](repeating: 0xa5, count: 16_384),
    observeWipe: { bytes in observation.record(bytes) })
  let originalAddress = data.withUnsafeBytes { bytes in
    bytes.baseAddress.map { UInt(bitPattern: $0) } ?? 0
  }
  #expect(originalAddress != 0)
  data = Data()
  let (wipedAddress, zeroed) = observation.snapshot()
  #expect(wipedAddress == originalAddress)
  #expect(zeroed)
}

@Test func decodedClaimsResultWipesItsOriginalStorage() {
  var result = ReallyMeProtoJoseJwtClaimsResult()
  result.claimsJson = Data(repeating: 0xa5, count: 16_384)
  var selected = ReallyMeProtoJoseJwtDecodeUnsignedResponse()
  selected.outcome = .result(result)
  result = ReallyMeProtoJoseJwtClaimsResult()
  var response = ReallyMeProtoJoseOperationResponse()
  response.response = .jwtDecodeUnsigned(selected)
  selected = ReallyMeProtoJoseJwtDecodeUnsignedResponse()
  let originalAddress = response.jwtDecodeUnsigned.result.claimsJson.withUnsafeBytes { bytes in
    bytes.baseAddress.map { UInt(bitPattern: $0) } ?? 0
  }
  #expect(originalAddress != 0)

  var responseCase = ReallyMeJOSEMemory.take(&response.response)
  guard case .jwtDecodeUnsigned(var extracted)? = responseCase else {
    Issue.record("claims response branch was not retained")
    return
  }
  responseCase = nil
  var outcome = ReallyMeJOSEMemory.take(&extracted.outcome)
  guard case .result(var ownedResult)? = ReallyMeJOSEMemory.take(&outcome) else {
    Issue.record("claims result branch was not retained")
    return
  }
  var wipedAddress: UInt = 0
  var zeroed = false
  ReallyMeJOSEMemory.clearOwned(
    &ownedResult.claimsJson,
    observeWipe: { bytes in
      wipedAddress = bytes.baseAddress.map { UInt(bitPattern: $0) } ?? 0
      zeroed = bytes.allSatisfy { $0 == 0 }
    })
  #expect(wipedAddress == originalAddress)
  #expect(zeroed)
}

@Test func jwsKnownAnswerAndTypedFailure() throws {
  let jose = try configuredJOSE()
  let publicKey = try bytes(
    hex: "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
  )
  let compact =
    "eyJhbGciOiJFZERTQSJ9.cmVhbGx5bWUtY29uZm9ybWFuY2UtY2lk.V-aqJPOjWYJ7P8hK-oyiqUsjO1kjXPsUp7YbXcTu2oXEJtElJoidqgSomnnsVBdING1fzza_rZwkdaE1RRYGDg"
  try jose.verifyJWS(algorithm: .edDSA, compact: compact, publicKey: publicKey)

  #expect(throws: ReallyMeJOSEError.jose(branch: .primitive, reason: .jwsInvalidSignature)) {
    try jose.verifyJWS(
      algorithm: .edDSA,
      compact: compact.replacingOccurrences(of: "V-aq", with: "A-aq"),
      publicKey: publicKey
    )
  }
}

@Test func jwsSigningUsesCanonicalRustRoute() throws {
  let jose = try configuredJOSE()
  let privateKey = try bytes(
    hex: "0909090909090909090909090909090909090909090909090909090909090909"
  )
  let publicKey = try bytes(
    hex: "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
  )
  let compact = try jose.signJWS(
    algorithm: .edDSA,
    privateKey: privateKey,
    payload: Array("stage-14-jws".utf8)
  )
  try jose.verifyJWS(algorithm: .edDSA, compact: compact, publicKey: publicKey)
}

@Test func unsignedJWTAndDirectJWERoundTrip() throws {
  let jose = try configuredJOSE()
  let claims = Array(#"{"sub":"stage-14"}"#.utf8)
  let unsigned = try jose.encodeUnsignedJWT(claimsJSON: claims)
  #expect(try jose.decodeUnsignedJWT(unsigned) == claims)

  let key = [UInt8](repeating: 8, count: 16)
  let plaintext = Array("stage-14 plaintext".utf8)
  let encrypted = try jose.encryptJWE(
    keyManagementAlgorithm: .direct,
    contentEncryptionAlgorithm: .a128GCM,
    key: key,
    plaintext: plaintext,
    keyIdentifier: "stage-14",
    compressionAlgorithm: .deflate
  )
  let decrypted = try jose.decryptJWE(
    compact: encrypted,
    keyManagementAlgorithm: .direct,
    contentEncryptionAlgorithm: .a128GCM,
    key: key,
    headerPolicy: ReallyMeJOSEJWEHeaderPolicy(
      requireKeyIdentifier: true,
      expectedKeyIdentifier: "stage-14",
      allowedCompressionAlgorithms: [.deflate]
    )
  )
  #expect(decrypted == plaintext)
}

@Test func signedJWTAndPolicyRoundTrip() throws {
  let jose = try configuredJOSE()
  let privateKey = try bytes(
    hex: "0909090909090909090909090909090909090909090909090909090909090909"
  )
  let publicKey = try bytes(
    hex: "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
  )
  let jwk = Array(
    #"{"alg":"EdDSA","crv":"Ed25519","kid":"k-ed","kty":"OKP","use":"sig","x":"_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"}"#
      .utf8)
  let claims = Array(#"{"sub":"stage-14-signed"}"#.utf8)
  let compact = try jose.signJWT(
    claimsJSON: claims,
    jwkJSON: jwk,
    privateKey: privateKey
  )
  let verified = try jose.verifyJWT(
    compact: compact,
    jwkJSON: jwk,
    publicKey: publicKey,
    signatureOnly: true
  )
  #expect(verified == claims)
}

@Test func jwtExpectedIssuerAndSubjectRemainPresenceSensitive() throws {
  let jose = try configuredJOSE()
  let privateKey = try bytes(
    hex: "0909090909090909090909090909090909090909090909090909090909090909"
  )
  let publicKey = try bytes(
    hex: "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
  )
  let jwk = Array(
    #"{"alg":"EdDSA","crv":"Ed25519","kid":"k-ed","kty":"OKP","use":"sig","x":"_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"}"#
      .utf8
  )
  let claims = Array(#"{"aud":"recipient","iss":"trusted","sub":"alice","exp":1720000100}"#.utf8)
  let compact = try jose.signJWT(claimsJSON: claims, jwkJSON: jwk, privateKey: privateKey)
  let policy = { (issuer: String?, subject: String?) in
    ReallyMeJOSEJWTTemporalPolicy(
      requireExpiration: true,
      requireNotBefore: false,
      requireIssuedAt: false,
      clockSkewSeconds: 0,
      maximumFutureIssuedAtSkewSeconds: 0,
      nowUnix: 1_720_000_000,
      expectedAudience: "recipient",
      expectedIssuer: issuer,
      expectedSubject: subject
    )
  }

  #expect(
    try jose.verifyJWT(
      compact: compact, jwkJSON: jwk, publicKey: publicKey,
      temporalPolicy: policy(nil, nil)
    ) == claims)
  #expect(
    try jose.verifyJWT(
      compact: compact, jwkJSON: jwk, publicKey: publicKey,
      temporalPolicy: policy("trusted", "alice")
    ) == claims)
  for (issuer, subject) in [("", nil), (nil, "")] {
    #expect(
      throws: ReallyMeJOSEError.jose(
        branch: .primitive, reason: .jwtInvalidVerificationPolicy
      )
    ) {
      try jose.verifyJWT(
        compact: compact, jwkJSON: jwk, publicKey: publicKey,
        temporalPolicy: policy(issuer, subject)
      )
    }
  }
  #expect(
    throws: ReallyMeJOSEError.jose(
      branch: .primitive, reason: .jwtSubjectMismatch
    )
  ) {
    try jose.verifyJWT(
      compact: compact, jwkJSON: jwk, publicKey: publicKey,
      temporalPolicy: policy("trusted", "other")
    )
  }
}

@Test func oversizedManagedInputFailsBeforeNativeCopy() throws {
  let jose = try configuredJOSE()
  let oversized = String(repeating: "a", count: 1_398_104)
  #expect(
    throws: ReallyMeJOSEError.jose(
      branch: .primitive,
      reason: .commonResourceLimitExceeded
    )
  ) {
    try jose.verifyJWS(algorithm: .edDSA, compact: oversized, publicKey: [])
  }
}

#if REALLYME_JOSE_LINKED_FFI
  @Test func linkedXCFrameworkExecutesOperationContract() throws {
    let jose = try ReallyMeJOSE()
    let claims = Array(#"{"sub":"linked-stage-14"}"#.utf8)
    let compact = try jose.encodeUnsignedJWT(claimsJSON: claims)
    #expect(try jose.decodeUnsignedJWT(compact) == claims)
  }
#endif

@Test func providerErrorReasonsMustBelongToTheirBranches() throws {
  let cases: [(ReallyMeJOSEErrorBranch, ReallyMeProtoJoseErrorReason, ReallyMeJOSEErrorReason)] = [
    (.primitive, .jwsInvalidSignature, .jwsInvalidSignature),
    (.provider, .providerUnavailable, .providerUnavailable),
    (.backend, .backendInternal, .backendInternal),
  ]
  for (expectedBranch, protoReason, reason) in cases {
    for branch in [ReallyMeJOSEErrorBranch.primitive, .provider, .backend] {
      var error = ReallyMeProtoJoseError()
      switch branch {
      case .primitive:
        var value = ReallyMeProtoJosePrimitiveError()
        value.reason = protoReason
        error.error = .primitive(value)
      case .provider:
        var value = ReallyMeProtoJoseProviderError()
        value.reason = protoReason
        error.error = .provider(value)
      case .backend:
        var value = ReallyMeProtoJoseBackendError()
        value.reason = protoReason
        error.error = .backend(value)
      }
      let expected: ReallyMeJOSEError =
        branch == expectedBranch
        ? .jose(branch: branch, reason: reason) : .malformedProviderResponse
      #expect(throws: expected) {
        throw try sdkError(error)
      }
    }
  }
}
