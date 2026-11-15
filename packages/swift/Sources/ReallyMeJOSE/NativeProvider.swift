// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
#endif

private let expectedJoseABIVersion: UInt32 = JoseContractValues.nativeAbiVersion

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
private typealias ExecuteOwnedFunction =
  @convention(c) (
    UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<OpaquePointer?>?
  ) -> Int32
private typealias ViewOwnedFunction =
  @convention(c) (
    UInt32, OpaquePointer?, UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
    UnsafeMutablePointer<UInt>?
  ) -> Int32
private typealias ReleaseOwnedFunction =
  @convention(c) (UInt32, UnsafeMutablePointer<OpaquePointer?>?) -> Int32

private struct OwnedResponseFunctions: Sendable {
  let binary: ExecuteOwnedFunction
  let json: ExecuteOwnedFunction
  let view: ViewOwnedFunction
  let release: ReleaseOwnedFunction
}

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
public final class ReallyMeJOSENativeLibrary: Sendable {
  // Store the immutable address value rather than a non-Sendable pointer. The
  // native image remains owned by this instance and is closed only at deinit.
  private let handleAddress: UInt

  public init(path: String) throws(ReallyMeJOSEError) {
    #if canImport(Darwin)
      guard FileManager.default.fileExists(atPath: path) else {
        throw ReallyMeJOSEError.nativeLibraryNotFound
      }
      guard let loaded = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
        throw ReallyMeJOSEError.nativeLibraryLoadFailed
      }
      handleAddress = UInt(bitPattern: loaded)
    #else
      _ = path
      throw ReallyMeJOSEError.unsupportedPlatform
    #endif
  }

  deinit {
    #if canImport(Darwin)
      if let handle = UnsafeMutableRawPointer(bitPattern: handleAddress) {
        dlclose(handle)
      }
    #endif
  }

  fileprivate func load<Function>(
    _ symbol: StaticString,
    as _: Function.Type
  ) throws(ReallyMeJOSEError) -> Function {
    #if canImport(Darwin)
      guard let handle = UnsafeMutableRawPointer(bitPattern: handleAddress) else {
        throw ReallyMeJOSEError.nativeLibraryLoadFailed
      }
      guard let raw = dlsym(handle, symbol.description) else {
        throw ReallyMeJOSEError.nativeSymbolMissing
      }
      return unsafeBitCast(raw, to: Function.self)
    #else
      _ = symbol
      throw ReallyMeJOSEError.unsupportedPlatform
    #endif
  }

  fileprivate func hasSymbol(_ symbol: StaticString) -> Bool {
    #if canImport(Darwin)
      guard let handle = UnsafeMutableRawPointer(bitPattern: handleAddress) else {
        return false
      }
      return dlsym(handle, symbol.description) != nil
    #else
      return false
    #endif
  }
}

protocol ReallyMeJOSENativeProvider: Sendable {
  var maximumBinaryRequestBytes: Int { get }
  var maximumJSONRequestBytes: Int { get }
  func executeBinary(_ request: [UInt8]) throws(ReallyMeJOSEError) -> [UInt8]
  func executeJSON(_ request: [UInt8]) throws(ReallyMeJOSEError) -> [UInt8]
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
  @_silgen_name("rm_jose_execute_owned_operation_v1")
  private func linkedExecuteOwnedBinary(
    _ version: UInt32,
    _ request: UnsafePointer<UInt8>?,
    _ requestLength: Int,
    _ owner: UnsafeMutablePointer<OpaquePointer?>?
  ) -> Int32
  @_silgen_name("rm_jose_execute_owned_operation_json_v1")
  private func linkedExecuteOwnedJSON(
    _ version: UInt32,
    _ request: UnsafePointer<UInt8>?,
    _ requestLength: Int,
    _ owner: UnsafeMutablePointer<OpaquePointer?>?
  ) -> Int32
  @_silgen_name("rm_jose_owned_response_view_v1")
  private func linkedOwnedResponseView(
    _ version: UInt32,
    _ owner: OpaquePointer?,
    _ bytes: UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
    _ length: UnsafeMutablePointer<UInt>?
  ) -> Int32
  @_silgen_name("rm_jose_owned_response_release_v1")
  private func linkedOwnedResponseRelease(
    _ version: UInt32,
    _ owner: UnsafeMutablePointer<OpaquePointer?>?
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
  private let owned: OwnedResponseFunctions?
  let maximumBinaryRequestBytes: Int
  let maximumJSONRequestBytes: Int
  private let maximumResponseBytes: Int

  #if REALLYME_JOSE_LINKED_FFI
    init() throws(ReallyMeJOSEError) {
      try Self.requireCompatibleABI(linkedABIVersion())
      maximumBinaryRequestBytes = try Self.validLimit(linkedMaximumRequestBytes())
      maximumJSONRequestBytes = try Self.validLimit(linkedMaximumJSONRequestBytes())
      maximumResponseBytes = try Self.validLimit(linkedMaximumResponseBytes())
      library = nil
      binaryFunction = linkedExecuteBinary
      jsonFunction = linkedExecuteJSON
      zeroizeFunction = linkedZeroize
      owned = OwnedResponseFunctions(
        binary: linkedExecuteOwnedBinary, json: linkedExecuteOwnedJSON,
        view: linkedOwnedResponseView, release: linkedOwnedResponseRelease)
    }
  #endif

  init(library: ReallyMeJOSENativeLibrary) throws(ReallyMeJOSEError) {
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
    if library.hasSymbol("rm_jose_execute_owned_operation_v1")
      || library.hasSymbol("rm_jose_execute_owned_operation_json_v1")
      || library.hasSymbol("rm_jose_owned_response_view_v1")
      || library.hasSymbol("rm_jose_owned_response_release_v1")
    {
      owned = try OwnedResponseFunctions(
        binary: library.load("rm_jose_execute_owned_operation_v1", as: ExecuteOwnedFunction.self),
        json: library.load(
          "rm_jose_execute_owned_operation_json_v1", as: ExecuteOwnedFunction.self),
        view: library.load("rm_jose_owned_response_view_v1", as: ViewOwnedFunction.self),
        release: library.load("rm_jose_owned_response_release_v1", as: ReleaseOwnedFunction.self)
      )
    } else {
      owned = nil
    }
  }

  func executeBinary(_ request: [UInt8]) throws(ReallyMeJOSEError) -> [UInt8] {
    if let owned {
      return try executeOwnedNativeRequest(
        request, limit: maximumBinaryRequestBytes, maximumResponseBytes: maximumResponseBytes,
        invoke: owned.binary, view: owned.view, release: owned.release)
    }
    return try executeNativeRequest(
      request, limit: maximumBinaryRequestBytes, maximumResponseBytes: maximumResponseBytes,
      invoke: binaryFunction, clear: clearOwned)
  }

  func executeJSON(_ request: [UInt8]) throws(ReallyMeJOSEError) -> [UInt8] {
    if let owned {
      return try executeOwnedNativeRequest(
        request, limit: maximumJSONRequestBytes, maximumResponseBytes: maximumResponseBytes,
        invoke: owned.json, view: owned.view, release: owned.release)
    }
    return try executeNativeRequest(
      request, limit: maximumJSONRequestBytes, maximumResponseBytes: maximumResponseBytes,
      invoke: jsonFunction, clear: clearOwned)
  }

  func clearOwned(_ bytes: inout [UInt8]) {
    let status = bytes.withUnsafeMutableBufferPointer { buffer in
      zeroizeFunction(expectedJoseABIVersion, buffer.baseAddress, buffer.count)
    }
    if status != NativeStatus.success {
      ReallyMeJOSEMemory.clearOwned(&bytes)
    }
  }

  private static func requireCompatibleABI(_ actual: UInt32) throws(ReallyMeJOSEError) {
    guard actual == expectedJoseABIVersion else {
      throw ReallyMeJOSEError.incompatibleABI
    }
  }

  private static func validLimit(_ value: UInt) throws(ReallyMeJOSEError) -> Int {
    guard let converted = Int(exactly: value), converted > 0 else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    return converted
  }
}

func executeOwnedNativeRequest(
  _ request: [UInt8],
  limit: Int,
  maximumResponseBytes: Int,
  invoke: (UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<OpaquePointer?>?) -> Int32,
  view: (
    UInt32, OpaquePointer?, UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
    UnsafeMutablePointer<UInt>?
  ) -> Int32,
  release: (UInt32, UnsafeMutablePointer<OpaquePointer?>?) -> Int32
) throws(ReallyMeJOSEError) -> [UInt8] {
  try requireNativeRequestLimit(request.count, limit: limit)
  var owner: OpaquePointer?
  var releaseStatus = NativeStatus.success
  var response: [UInt8]
  do {
    // Keep the allocation live through the copy and release it on every exit
    // after ownership transfers, including a rejected view.
    defer {
      if owner != nil {
        releaseStatus = release(expectedJoseABIVersion, &owner)
      }
    }
    let status = request.withUnsafeBufferPointer {
      invoke(expectedJoseABIVersion, $0.baseAddress, $0.count, &owner)
    }
    try throwTransportStatus(status)
    guard let owner else { throw ReallyMeJOSEError.malformedProviderResponse }

    var data: UnsafePointer<UInt8>?
    var lengthOut: UInt = 0
    try throwTransportStatus(view(expectedJoseABIVersion, owner, &data, &lengthOut))
    guard let data,
      let length = Int(exactly: lengthOut),
      length > 0,
      length <= maximumResponseBytes
    else {
      throw ReallyMeJOSEError.malformedProviderResponse
    }
    response = Array(UnsafeBufferPointer(start: data, count: length))
  }
  if releaseStatus != NativeStatus.success || owner != nil {
    ReallyMeJOSEMemory.clearOwned(&response)
    try throwTransportStatus(releaseStatus)
    throw ReallyMeJOSEError.malformedProviderResponse
  }
  return response
}

private func requireNativeRequestLimit(_ count: Int, limit: Int) throws(ReallyMeJOSEError) {
  guard count <= limit else {
    throw ReallyMeJOSEError.jose(branch: .primitive, reason: .commonResourceLimitExceeded)
  }
}

func executeNativeRequest(
  _ request: [UInt8],
  limit: Int,
  maximumResponseBytes: Int,
  invoke: (
    UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<Int>?
  ) -> Int32,
  clear: (inout [UInt8]) -> Void
) throws(ReallyMeJOSEError) -> [UInt8] {
  try requireNativeRequestLimit(request.count, limit: limit)
  var producedLength = 0
  let probe = request.withUnsafeBufferPointer { requestBuffer in
    invoke(
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
    try throwTransportStatus(probe)
    throw ReallyMeJOSEError.malformedProviderResponse
  }

  var output = [UInt8](repeating: 0, count: producedLength)
  var returnOutput = false
  defer {
    if !returnOutput {
      clear(&output)
    }
  }
  let capacity = output.count
  // Require an independent length report from the write call.
  producedLength = 0
  let status = request.withUnsafeBufferPointer { requestBuffer in
    output.withUnsafeMutableBufferPointer { outputBuffer in
      invoke(
        expectedJoseABIVersion,
        requestBuffer.baseAddress,
        requestBuffer.count,
        outputBuffer.baseAddress,
        capacity,
        &producedLength
      )
    }
  }
  try throwTransportStatus(status)
  guard producedLength > 0, producedLength <= capacity else {
    throw ReallyMeJOSEError.malformedProviderResponse
  }

  // Each call executes independently. Preserve a shorter complete envelope
  // for typed decoding and erase the entire temporary allocation.
  if producedLength < capacity {
    return output.withUnsafeBufferPointer { bytes in
      Array(bytes.prefix(producedLength))
    }
  }
  returnOutput = true
  return output
}

private func throwTransportStatus(_ status: Int32) throws(ReallyMeJOSEError) {
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
