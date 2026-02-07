// swift-tools-version: 6.2
import PackageDescription

let package = Package(
  name: "mac-n-keys",
  platforms: [.macOS(.v26)],
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
    .package(url: "https://github.com/attaswift/BigInt", from: "5.3.0"),
  ],
  targets: [
    .target(
      name: "Lib",
      dependencies: [
        .product(name: "BigInt", package: "BigInt"),
      ],
      path: "Sources/Lib",
      swiftSettings: swiftSettings
    ),
    .executableTarget(
      name: "mac-n-keys",
      dependencies: [
        "Lib",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
      ],
      path: "Sources/MacNKeys",
      swiftSettings: swiftSettings
    ),
    .executableTarget(
      name: "age-plugin-se",
      dependencies: [
        "Lib",
      ],
      path: "Sources/AgePluginSE",
      swiftSettings: swiftSettings
    ),
    .testTarget(
      name: "Tests",
      dependencies: [
        "Lib",
        .product(name: "BigInt", package: "BigInt"),
      ],
      path: "Tests",
      swiftSettings: swiftSettings
    ),
  ]
)

var swiftSettings: [PackageDescription.SwiftSetting] {
  [
    .swiftLanguageMode(.v6),
  ]
}
