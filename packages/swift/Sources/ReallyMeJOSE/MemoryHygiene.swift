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
  static func clearOwned(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buffer in clear(buffer) }
  }

  static func clearOwned(_ bytes: inout Data) {
    bytes.withUnsafeMutableBytes { buffer in clear(buffer) }
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
