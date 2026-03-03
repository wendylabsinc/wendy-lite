// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SwiftBlink",
    dependencies: [
        .package(url: "https://github.com/apple/swift-container-plugin", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "CWendy",
            path: "Sources/CWendy"
        ),
        .executableTarget(
            name: "SwiftBlink",
            dependencies: ["CWendy"],
            path: "Sources/SwiftBlink",
            swiftSettings: [
                .enableExperimentalFeature("Embedded"),
                .unsafeFlags(["-wmo"]),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-Xclang-linker", "-nostdlib",
                    "-Xlinker", "--no-entry",
                    "-Xlinker", "--export=_start",
                    "-Xlinker", "--allow-undefined",
                    "-Xlinker", "--initial-memory=131072",
                    "-Xlinker", "-z", "-Xlinker", "stack-size=8192",
                ])
            ]
        )
    ]
)
