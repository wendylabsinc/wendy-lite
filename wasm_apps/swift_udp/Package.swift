// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "SwiftUdp",
    dependencies: [
        .package(path: "../.."),                                     // wendy-lite root (provides WendyLite)
        .package(url: "https://github.com/wendylabsinc/wendy-net.git",
                 branch: "main",
                 traits: ["WendyLite"]),                             // WendyNet, embedded backend
        .package(url: "https://github.com/apple/swift-container-plugin", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "CWendy",
            path: "Sources/CWendy"
        ),
        .executableTarget(
            name: "SwiftUdp",
            dependencies: [
                .product(name: "WendyLite", package: "wendy-lite"),
                .product(name: "WendyNet", package: "wendy-net"),
            ],
            path: "Sources/SwiftUdp",
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
