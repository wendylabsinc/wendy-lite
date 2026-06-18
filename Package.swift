// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "WendyLite",
    products: [
        .library(name: "WendyLite", targets: ["WendyLite"]),
        .library(name: "CWendyLite", targets: ["CWendyLite"]),
    ],
    targets: [
        .target(
            name: "CWendyLite",
            path: "Sources/CWendyLite"
        ),
        .target(
            name: "WendyLite",
            dependencies: ["CWendyLite"],
            path: "Sources/WendyLite",
            swiftSettings: [
                .enableExperimentalFeature("Embedded"),
                .unsafeFlags(["-wmo"]),
            ]
        ),
    ]
)
