// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "WendyLite",
    products: [
        .library(name: "WendyLite", targets: ["WendyLite"]),
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
