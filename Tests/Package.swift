// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LoggersTests",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "t_log_formats",
            targets: ["LogFormatsTests"]
        ),
        .executable(
            name: "t_standard_logger",
            targets: ["StandardLoggerTests"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/leviouwendijk/Primitives.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Testing.git", branch: "master"),
        .package(path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "LogFormatsTests",
            dependencies: [
                .product(name: "LogFormats", package: "Loggers"),
                .product(name: "LogFormatsParsing", package: "Loggers"),
                .product(name: "LogCollection", package: "Loggers"),
                .product(name: "Primitives", package: "Primitives"),
                .product(name: "Testing", package: "Testing"),
            ]
        ),
        .executableTarget(
            name: "StandardLoggerTests",
            dependencies: [
                .product(name: "Loggers", package: "Loggers"),
                .product(name: "Testing", package: "Testing"),
            ]
        ),
    ]
)
