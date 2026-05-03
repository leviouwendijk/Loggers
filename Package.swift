// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Loggers",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "Loggers",
            targets: ["Loggers"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/leviouwendijk/Milieu.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Writers.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "Loggers",
            dependencies: [
                .product(name: "Milieu", package: "Milieu"),
                .product(name: "Writers", package: "Writers"),
            ]
        ),
        .testTarget(
            name: "LoggersTests",
            dependencies: ["Loggers"]
        ),
    ]
)
