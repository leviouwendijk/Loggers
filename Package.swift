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
        // Log record types (syslog, CEF, key=value) as Primitives invariants.
        .library(
            name: "LogFormats",
            targets: ["LogFormats"]
        ),
        // Parsers producing LogFormats values. No dependencies beyond LogFormats.
        .library(
            name: "LogFormatsParsing",
            targets: ["LogFormatsParsing"]
        ),
        // Wire contract of a log collector (stored entry, query, responses), e.g. syslogger.
        .library(
            name: "LogCollection",
            targets: ["LogCollection"]
        ),
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
        .package(url: "https://github.com/leviouwendijk/Milieu.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Writers.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Primitives.git", branch: "master"),
        .package(url: "https://github.com/leviouwendijk/Testing.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "Loggers",
            dependencies: [
                .product(name: "Milieu", package: "Milieu"),
                .product(name: "Writers", package: "Writers"),
            ]
        ),
        .target(
            name: "LogFormats",
            dependencies: [
                .product(name: "Primitives", package: "Primitives"),
            ]
        ),
        .target(
            name: "LogFormatsParsing",
            dependencies: [
                "LogFormats",
            ]
        ),
        .target(
            name: "LogCollection",
            dependencies: [
                "LogFormats",
                .product(name: "Primitives", package: "Primitives"),
            ]
        ),
        .executableTarget(
            name: "LogFormatsTests",
            dependencies: [
                "LogFormats",
                "LogFormatsParsing",
                "LogCollection",
                .product(name: "Primitives", package: "Primitives"),
                .product(name: "Testing", package: "Testing"),
            ],
            path: "Testing/LogFormatsTests"
        ),
        .executableTarget(
            name: "StandardLoggerTests",
            dependencies: [
                "Loggers",
                .product(name: "Testing", package: "Testing"),
            ],
            path: "Testing/StandardLoggerTests"
        ),
    ]
)
