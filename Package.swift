// swift-tools-version: 6.3
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import PackageDescription

let ffiArtifactChecksum = "d103981eef93940ef26a452d93d9e7616ff94c1b5aa0894845d0b983889020ee"
let ffiArtifactVersion = "0.3.0"
let ffiArtifactLocalPathOverride = ""
// Source-tree CI exercises runtime loading before testing the linked release
// artifact. Require a repository-local marker as a second gate so an inherited
// environment variable cannot silently remove the public binary target.
let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let runtimeFfiOverrideMarkerPath = "\(packageRoot)/.reallyme-jose-runtime-ffi"
let runtimeFfiOverrideRequested =
  ProcessInfo.processInfo.environment["REALLYME_JOSE_SWIFTPM_RUNTIME_FFI"] == "1"
let useRuntimeFfiProvider =
  runtimeFfiOverrideRequested
  && FileManager.default.fileExists(atPath: runtimeFfiOverrideMarkerPath)

var joseDependencies: [Target.Dependency] = [
  "ReallyMeJOSEProto",
  .product(name: "SwiftProtobuf", package: "swift-protobuf"),
]
var joseSettings: [SwiftSetting] = []
var joseTestSettings: [SwiftSetting] = []
var packageTargets: [Target] = []

if !useRuntimeFfiProvider {
  joseDependencies.append("ReallyMeJOSEFFI")
  joseSettings.append(.define("REALLYME_JOSE_LINKED_FFI"))
  joseTestSettings.append(.define("REALLYME_JOSE_LINKED_FFI"))
  if ffiArtifactLocalPathOverride.isEmpty {
    packageTargets.append(
      .binaryTarget(
        name: "ReallyMeJOSEFFI",
        url:
          "https://github.com/reallyme/jose/releases/download/v\(ffiArtifactVersion)/ReallyMeJOSEFFI.xcframework.zip",
        checksum: ffiArtifactChecksum
      )
    )
  } else {
    packageTargets.append(
      .binaryTarget(name: "ReallyMeJOSEFFI", path: ffiArtifactLocalPathOverride))
  }
}

packageTargets.append(
  .target(
    name: "ReallyMeJOSE",
    dependencies: joseDependencies,
    path: "packages/swift/Sources/ReallyMeJOSE",
    swiftSettings: joseSettings
  )
)
packageTargets.append(
  .target(
    name: "ReallyMeJOSEProto",
    dependencies: [.product(name: "SwiftProtobuf", package: "swift-protobuf")],
    path: "gen/swift"
  )
)
packageTargets.append(
  .testTarget(
    name: "ReallyMeJOSETests",
    dependencies: ["ReallyMeJOSE"],
    path: "packages/swift/Tests/ReallyMeJOSETests",
    swiftSettings: joseTestSettings
  )
)

let package = Package(
  name: "reallyme-jose",
  platforms: [.macOS(.v13), .iOS(.v16)],
  products: [
    .library(name: "ReallyMeJOSE", targets: ["ReallyMeJOSE"]),
    .library(name: "ReallyMeJOSEProto", targets: ["ReallyMeJOSEProto"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.38.1")
  ],
  targets: packageTargets
)
