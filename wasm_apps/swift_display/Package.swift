// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SwiftDisplay",
    targets: [
        .target(
            name: "CWendy",
            path: "Sources/CWendy"
        ),
        .executableTarget(
            name: "SwiftDisplay",
            dependencies: ["CWendy"],
            path: "Sources/SwiftDisplay",
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
                    "-Xlinker", "--initial-memory=65536",
                    "-Xlinker", "-z", "-Xlinker", "stack-size=8192",
                ])
            ]
        )
    ]
)
