// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
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
    #else
      #error("ReallyMeJOSE supports Swift only on Darwin platforms with non-elidable memset_s")
    #endif
  }
}
