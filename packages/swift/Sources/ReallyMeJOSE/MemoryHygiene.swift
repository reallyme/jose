// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#elseif canImport(Musl)
  import Musl
#endif

enum ReallyMeJOSEMemory {
  static func take<Value>(_ slot: inout Value?) -> Value? {
    var value: Value? = nil
    swap(&slot, &value)
    return value
  }

  // SwiftProtobuf value copies can share Data storage. Give every facade-owned
  // request field a wiping storage owner so the original allocation is erased
  // when its last alias is released, even if later mutations trigger COW.
  static func ownedData(
    _ bytes: [UInt8],
    observeWipe: (@Sendable (UnsafeRawBufferPointer) -> Void)? = nil
  ) -> Data {
    guard bytes.isEmpty == false else { return Data() }
    let storage = UnsafeMutableRawPointer.allocate(
      byteCount: bytes.count,
      alignment: MemoryLayout<UInt8>.alignment)
    let destination = UnsafeMutableRawBufferPointer(start: storage, count: bytes.count)
    _ = bytes.withUnsafeBytes { source in
      source.copyBytes(to: destination)
    }
    return Data(
      bytesNoCopy: storage, count: bytes.count,
      deallocator: .custom { pointer, length in
        clear(UnsafeMutableRawBufferPointer(start: pointer, count: length))
        observeWipe?(UnsafeRawBufferPointer(start: pointer, count: length))
        pointer.deallocate()
      })
  }

  static func clearOwned(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buffer in clear(buffer) }
  }

  static func clearOwned(
    _ bytes: inout Data,
    observeWipe: ((UnsafeRawBufferPointer) -> Void)? = nil
  ) {
    bytes.withUnsafeMutableBytes { buffer in
      clear(buffer)
      observeWipe?(UnsafeRawBufferPointer(buffer))
    }
  }

  private static func clear(_ buffer: UnsafeMutableRawBufferPointer) {
    guard let baseAddress = buffer.baseAddress, !buffer.isEmpty else { return }
    #if canImport(Darwin)
      _ = memset_s(baseAddress, buffer.count, 0, buffer.count)
    #elseif canImport(Glibc) || canImport(Musl)
      // Linux libcs provide an explicit erasure primitive whose call cannot be
      // removed when the buffer becomes dead immediately after this function.
      explicit_bzero(baseAddress, buffer.count)
    #else
      #error("ReallyMeJOSE requires a platform-provided non-elidable memory erasure primitive")
    #endif
  }
}
