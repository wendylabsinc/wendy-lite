// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SwiftBlink",
    dependencies: [
        .package(path: "../.."),  // root wendy-lite package (provides WendyLite)
        .package(url: "https://github.com/apple/swift-container-plugin", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "CWendy",
            path: "Sources/CWendy"
        ),
        .executableTarget(
            name: "SwiftBlink",
            dependencies: [
                .product(name: "WendyLite", package: "wendy-lite"),
            ],
            path: "Sources/SwiftBlink",
            swiftSettings: [
                .enableExperimentalFeature("Embedded"),
                .unsafeFlags(["-wmo"]),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker", "--allow-undefined",
                    "-Xlinker", "--initial-memory=65536",
                    "-Xlinker", "--table-base=1",
                    "-Xlinker", "--strip-all",
                    "-Xlinker", "--export=malloc",
                    "-Xlinker", "--export=free",
                    "-Xlinker", "--export=wendy_handle_callback",
                    "-Xlinker", "-z", "-Xlinker", "stack-size=8192",
                ])
            ]
        )
    ]
)
