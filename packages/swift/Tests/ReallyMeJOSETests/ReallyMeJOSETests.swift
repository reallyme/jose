// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
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
    keyIdentifier: "stage-14"
  )
  let decrypted = try jose.decryptJWE(
    compact: encrypted,
    keyManagementAlgorithm: .direct,
    contentEncryptionAlgorithm: .a128GCM,
    key: key,
    headerPolicy: ReallyMeJOSEJWEHeaderPolicy(
      requireKeyIdentifier: true,
      expectedKeyIdentifier: "stage-14"
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
