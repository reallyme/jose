// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeJOSEProto
import Testing

@testable import ReallyMeJOSE

private struct ResponseSequence {
  let sizing: [UInt8]
  let writing: [UInt8]
  var capacityChecks: [Int] = []
  var writeAddress: UInt?
  var clearedAddress: UInt?
  var clearedBytes: [UInt8] = []

  mutating func invoke(
    version: UInt32,
    request: UnsafePointer<UInt8>?,
    count: Int,
    output: UnsafeMutablePointer<UInt8>?,
    capacity: Int,
    produced: UnsafeMutablePointer<Int>?
  ) -> Int32 {
    #expect(version == 1)
    #expect(count == 1)
    #expect(request?.pointee == 0xa5)
    capacityChecks.append(capacity)
    if capacity == 0 {
      #expect(output == nil)
      produced?.pointee = sizing.count
      return -5
    }
    guard let output else { return -1 }
    #expect(produced?.pointee == 0)
    writeAddress = UInt(bitPattern: output)
    // Dirty the whole allocation so cleanup is observable even when the
    // ABI status rejects the write. This models a defensive adapter check.
    UnsafeMutableBufferPointer(start: output, count: capacity).update(repeating: 0xa5)
    produced?.pointee = writing.count
    guard writing.count <= capacity else { return -5 }
    _ = writing.withUnsafeBufferPointer {
      UnsafeMutableBufferPointer(start: output, count: writing.count).update(fromContentsOf: $0)
    }
    return 0
  }

  mutating func clear(_ bytes: inout [UInt8]) {
    ReallyMeJOSEMemory.clearOwned(&bytes)
    clearedAddress = bytes.withUnsafeBytes { $0.baseAddress.map { UInt(bitPattern: $0) } }
    clearedBytes = bytes
  }
}

private func encryptionResponses() throws -> (success: [UInt8], failure: [UInt8]) {
  var compact = ReallyMeProtoJoseCompactResult()
  compact.compact =
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA"
  var provider = ReallyMeProtoJoseProviderError()
  provider.reason = .providerRandomnessUnavailable
  var providerError = ReallyMeProtoJoseError()
  providerError.error = .provider(provider)
  var jwe = ReallyMeProtoJoseJweEncryptResponse()
  var envelope = ReallyMeProtoJoseOperationResponse()
  envelope.contractVersion = .v1
  jwe.outcome = .result(compact)
  envelope.response = .jweEncrypt(jwe)
  let success: [UInt8] = try envelope.serializedBytes()
  jwe.outcome = .error(providerError)
  envelope.response = .jweEncrypt(jwe)
  let failure: [UInt8] = try envelope.serializedBytes()
  return (success, failure)
}

@Test func shorterWritePreservesTheTypedFailureAndWipesTheProbedAllocation() throws {
  let frames = try encryptionResponses()
  #expect(frames.failure.count < frames.success.count)
  var sequence = ResponseSequence(sizing: frames.success, writing: frames.failure)

  let bytes = try executeNativeRequest(
    [0xa5], limit: 1024, maximumResponseBytes: 1024,
    invoke: { version, request, count, output, capacity, produced in
      sequence.invoke(
        version: version, request: request, count: count, output: output,
        capacity: capacity, produced: produced)
    },
    clear: { sequence.clear(&$0) }
  )

  #expect(bytes == frames.failure)
  let envelope = try ReallyMeProtoJoseOperationResponse(serializedBytes: bytes)
  guard case .jweEncrypt(let operation)? = envelope.response,
    case .error(let error)? = operation.outcome
  else {
    Issue.record("expected the shorter operation error")
    return
  }
  #expect(
    try sdkError(error) == .jose(branch: .provider, reason: .providerRandomnessUnavailable))
  #expect(sequence.capacityChecks == [0, frames.success.count])
  #expect(sequence.writeAddress != nil)
  #expect(sequence.clearedAddress == sequence.writeAddress)
  #expect(sequence.clearedBytes == [UInt8](repeating: 0, count: frames.success.count))
}

@Test func largerWriteSurfacesTransportFailureAndWipesTheProbedAllocation() throws {
  let frames = try encryptionResponses()
  var sequence = ResponseSequence(sizing: frames.failure, writing: frames.success)

  #expect(throws: ReallyMeJOSEError.malformedProviderResponse) {
    try executeNativeRequest(
      [0xa5], limit: 1024, maximumResponseBytes: 1024,
      invoke: { version, request, count, output, capacity, produced in
        sequence.invoke(
          version: version, request: request, count: count, output: output,
          capacity: capacity, produced: produced)
      },
      clear: { sequence.clear(&$0) }
    )
  }

  #expect(sequence.capacityChecks == [0, frames.failure.count])
  #expect(sequence.writeAddress != nil)
  #expect(sequence.clearedAddress == sequence.writeAddress)
  #expect(sequence.clearedBytes == [UInt8](repeating: 0, count: frames.failure.count))
}

@Test func ownedResponseExecutesOnceAndReleasesAfterTheCopy() throws {
  let frames = try encryptionResponses()
  for frame in [frames.success, frames.failure] {
    var storage = frame.map { $0 }
    var calls: [String] = []
    let bytes = try storage.withUnsafeMutableBufferPointer { buffer in
      let nativeOwner = OpaquePointer(buffer.baseAddress)
      return try executeOwnedNativeRequest(
        [0xa5], limit: 1024, maximumResponseBytes: 1024,
        invoke: { version, request, count, slot in
          calls.append("execute")
          #expect(version == 1)
          #expect(request?.pointee == 0xa5 && count == 1)
          #expect(slot != nil && slot?.pointee == nil)
          slot?.pointee = nativeOwner
          return 0
        },
        view: { version, owner, data, length in
          calls.append("view")
          #expect(version == 1 && owner == nativeOwner)
          data?.pointee = buffer.baseAddress.map { UnsafePointer($0) }
          length?.pointee = UInt(buffer.count)
          return 0
        },
        release: { version, slot in
          calls.append("release")
          #expect(version == 1 && slot?.pointee == nativeOwner)
          slot?.pointee = nil
          buffer.update(repeating: 0)
          return 0
        })
    }
    #expect(calls == ["execute", "view", "release"])
    #expect(bytes == frame)
    #expect(storage.allSatisfy { $0 == 0 })
  }
}

@Test func invalidOwnedViewStillReleasesTheAllocation() {
  var storage: [UInt8] = [0xa5]
  var releases = 0
  storage.withUnsafeMutableBufferPointer { buffer in
    let nativeOwner = OpaquePointer(buffer.baseAddress)
    #expect(throws: ReallyMeJOSEError.malformedProviderResponse) {
      try executeOwnedNativeRequest(
        [0xa5], limit: 1024, maximumResponseBytes: 1024,
        invoke: { _, _, _, slot in
          slot?.pointee = nativeOwner
          return 0
        },
        view: { _, _, data, length in
          data?.pointee = buffer.baseAddress.map { UnsafePointer($0) }
          length?.pointee = UInt.max
          return 0
        },
        release: { _, slot in
          #expect(slot?.pointee == nativeOwner)
          slot?.pointee = nil
          buffer.update(repeating: 0)
          releases += 1
          return 0
        })
    }
  }
  #expect(releases == 1)
  #expect(storage == [0])
}

@Test func rejectedOwnedExecutionSkipsTheViewAndNeedsNoRelease() {
  #expect(throws: ReallyMeJOSEError.incompatibleABI) {
    try executeOwnedNativeRequest(
      [0xa5], limit: 1024, maximumResponseBytes: 1024,
      invoke: { _, _, _, slot in
        #expect(slot != nil && slot?.pointee == nil)
        return -6
      },
      view: { _, _, _, _ in
        Issue.record("a failed execution cannot expose a view")
        return -1
      },
      release: { _, _ in
        Issue.record("a failed execution left the slot empty")
        return -1
      })
  }
}

@Test func ownedResponseIsDiscardedIfReleaseFails() {
  let storage: [UInt8] = [0xa5]
  storage.withUnsafeBufferPointer { buffer in
    let nativeOwner = OpaquePointer(buffer.baseAddress)
    #expect(throws: ReallyMeJOSEError.incompatibleABI) {
      try executeOwnedNativeRequest(
        [0xa5], limit: 1024, maximumResponseBytes: 1024,
        invoke: { _, _, _, slot in
          slot?.pointee = nativeOwner
          return 0
        },
        view: { _, _, data, length in
          data?.pointee = buffer.baseAddress
          length?.pointee = UInt(buffer.count)
          return 0
        },
        release: { _, slot in
          #expect(slot?.pointee == nativeOwner)
          return -6
        })
    }
  }
}
