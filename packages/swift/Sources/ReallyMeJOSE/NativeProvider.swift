// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
#endif

private let expectedJoseABIVersion: UInt32 = 1

private typealias ABIVersionFunction = @convention(c) () -> UInt32
private typealias SizeLimitFunction = @convention(c) () -> UInt
private typealias ExecuteFunction =
  @convention(c) (
    UInt32,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
  ) -> Int32
private typealias ZeroizeFunction =
  @convention(c) (
    UInt32,
    UnsafeMutablePointer<UInt8>?,
    Int
  ) -> Int32

private enum NativeStatus {
  static let success: Int32 = 0
  static let callerError: Int32 = -1
  static let providerError: Int32 = -2
  static let backendError: Int32 = -3
  static let panicCaught: Int32 = -4
  static let capacityMismatch: Int32 = -5
  static let unsupportedABI: Int32 = -6
}

/// Runtime-loaded native image. The handle remains alive while resolved symbols are callable.
public final class ReallyMeJOSENativeLibrary: @unchecked Sendable {
  fileprivate let handle: UnsafeMutableRawPointer

  public init(path: String) throws {
    #if canImport(Darwin)
      guard FileManager.default.fileExists(atPath: path) else {
        throw ReallyMeJOSEError.nativeLibraryNotFound
      }
      guard let loaded = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
        throw ReallyMeJOSEError.nativeLibraryLoadFailed
      }
      handle = loaded
    #else
      _ = path
      throw ReallyMeJOSEError.unsupportedPlatform
    #endif
  }

  deinit {
    #if canImport(Darwin)
      dlclose(handle)
    #endif
  }

  fileprivate func load<Function>(_ symbol: StaticString, as _: Function.Type) throws -> Function {
    #if canImport(Darwin)
      guard let raw = dlsym(handle, symbol.description) else {
        throw ReallyMeJOSEError.nativeSymbolMissing
      }
      return unsafeBitCast(raw, to: Function.self)
    #else
      _ = symbol
      throw ReallyMeJOSEError.unsupportedPlatform
    #endif
  }
}

protocol ReallyMeJOSENativeProvider: Sendable {
  var maximumBinaryRequestBytes: Int { get }
  var maximumJSONRequestBytes: Int { get }
  func executeBinary(_ request: [UInt8]) throws -> [UInt8]
  func executeJSON(_ request: [UInt8]) throws -> [UInt8]
  func clearOwned(_ bytes: inout [UInt8])
}

#if REALLYME_JOSE_LINKED_FFI
  @_silgen_name("rm_jose_abi_version")
  private func linkedABIVersion() -> UInt32
  @_silgen_name("rm_jose_max_request_bytes")
  private func linkedMaximumRequestBytes() -> UInt
  @_silgen_name("rm_jose_max_json_request_bytes")
  private func linkedMaximumJSONRequestBytes() -> UInt
  @_silgen_name("rm_jose_max_response_bytes")
  private func linkedMaximumResponseBytes() -> UInt
  @_silgen_name("rm_jose_execute_operation_v1")
  private func linkedExecuteBinary(
    _ version: UInt32,
    _ request: UnsafePointer<UInt8>?,
    _ requestLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?,
    _ outputCapacity: Int,
    _ producedLength: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_jose_execute_operation_json_v1")
  private func linkedExecuteJSON(
    _ version: UInt32,
    _ request: UnsafePointer<UInt8>?,
    _ requestLength: Int,
    _ output: UnsafeMutablePointer<UInt8>?,
    _ outputCapacity: Int,
    _ producedLength: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_jose_zeroize_buffer")
  private func linkedZeroize(
    _ version: UInt32,
    _ bytes: UnsafeMutablePointer<UInt8>?,
    _ length: Int
  ) -> Int32
#endif

struct ReallyMeJOSERustProvider: ReallyMeJOSENativeProvider {
  private let library: ReallyMeJOSENativeLibrary?
  private let binaryFunction: ExecuteFunction
  private let jsonFunction: ExecuteFunction
  private let zeroizeFunction: ZeroizeFunction
  let maximumBinaryRequestBytes: Int
  let maximumJSONRequestBytes: Int
  private let maximumResponseBytes: Int

  #if REALLYME_JOSE_LINKED_FFI
    init() throws {
      try Self.requireCompatibleABI(linkedABIVersion())
      maximumBinaryRequestBytes = try Self.validLimit(linkedMaximumRequestBytes())
      maximumJSONRequestBytes = try Self.validLimit(linkedMaximumJSONRequestBytes())
      maximumResponseBytes = try Self.validLimit(linkedMaximumResponseBytes())
      library = nil
      binaryFunction = linkedExecuteBinary
      jsonFunction = linkedExecuteJSON
      zeroizeFunction = linkedZeroize
    }
  #endif

  init(library: ReallyMeJOSENativeLibrary) throws {
    self.library = library
    let version = try library.load("rm_jose_abi_version", as: ABIVersionFunction.self)
    try Self.requireCompatibleABI(version())

    // Resolve no operational symbol until the image proves exact ABI compatibility.
    let binaryLimit = try library.load("rm_jose_max_request_bytes", as: SizeLimitFunction.self)
    let jsonLimit = try library.load("rm_jose_max_json_request_bytes", as: SizeLimitFunction.self)
    let responseLimit = try library.load("rm_jose_max_response_bytes", as: SizeLimitFunction.self)
    maximumBinaryRequestBytes = try Self.validLimit(binaryLimit())
    maximumJSONRequestBytes = try Self.validLimit(jsonLimit())
    maximumResponseBytes = try Self.validLimit(responseLimit())
    binaryFunction = try library.load("rm_jose_execute_operation_v1", as: ExecuteFunction.self)
    jsonFunction = try library.load("rm_jose_execute_operation_json_v1", as: ExecuteFunction.self)
    zeroizeFunction = try library.load("rm_jose_zeroize_buffer", as: ZeroizeFunction.self)
  }

  func executeBinary(_ request: [UInt8]) throws -> [UInt8] {
    try execute(request, limit: maximumBinaryRequestBytes, function: binaryFunction)
  }

  func executeJSON(_ request: [UInt8]) throws -> [UInt8] {
    try execute(request, limit: maximumJSONRequestBytes, function: jsonFunction)
  }

  func clearOwned(_ bytes: inout [UInt8]) {
    let status = bytes.withUnsafeMutableBufferPointer { buffer in
      zeroizeFunction(expectedJoseABIVersion, buffer.baseAddress, buffer.count)
    }
    if status != NativeStatus.success {
      ReallyMeJOSEMemory.clearOwned(&bytes)
    }
  }

  private func execute(
    _ request: [UInt8],
    limit: Int,
    function: ExecuteFunction
  ) throws -> [UInt8] {
    guard request.count <= limit else {
      throw ReallyMeJOSEError.jose(
        branch: .primitive,
        reason: .commonResourceLimitExceeded
      )
    }
    var producedLength = 0
    let probe = request.withUnsafeBufferPointer { requestBuffer in
      function(
        expectedJoseABIVersion,
        requestBuffer.baseAddress,
        request.count,
        nil,
        0,
        &producedLength
      )
    }
    guard probe == NativeStatus.capacityMismatch,
      producedLength > 0,
      producedLength <= maximumResponseBytes
    else {
      try Self.throwTransportStatus(probe)
      throw ReallyMeJOSEError.malformedProviderResponse
    }

    var output = [UInt8](repeating: 0, count: producedLength)
    let capacity = output.count
    let status = request.withUnsafeBufferPointer { requestBuffer in
      output.withUnsafeMutableBufferPointer { outputBuffer in
        function(
          expectedJoseABIVersion,
          requestBuffer.baseAddress,
          request.count,
          outputBuffer.baseAddress,
          capacity,
          &producedLength
        )
      }
    }
    do {
      try Self.throwTransportStatus(status)
      guard producedLength == output.count else {
        throw ReallyMeJOSEError.malformedProviderResponse
      }
      return output
    } catch {
      clearOwned(&output)
      throw error
    }
  }

  private static func requireCompatibleABI(_ actual: UInt32) throws {
    guard actual == expectedJoseABIVersion else {
      throw ReallyMeJOSEError.incompatibleABI
    }
  }

  private static func validLimit(_ value: UInt) throws -> Int {
    guard let converted = Int(exactly: value), converted > 0 else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    return converted
  }

  private static func throwTransportStatus(_ status: Int32) throws {
    switch status {
    case NativeStatus.success:
      return
    case NativeStatus.providerError:
      throw ReallyMeJOSEError.jose(branch: .provider, reason: .providerUnavailable)
    case NativeStatus.unsupportedABI:
      throw ReallyMeJOSEError.incompatibleABI
    case NativeStatus.callerError,
      NativeStatus.backendError,
      NativeStatus.panicCaught,
      NativeStatus.capacityMismatch:
      throw ReallyMeJOSEError.malformedProviderResponse
    default:
      throw ReallyMeJOSEError.malformedProviderResponse
    }
  }
}
