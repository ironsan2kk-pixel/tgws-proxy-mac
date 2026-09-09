// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "TGWSProxyMac",
    platforms: [.macOS(.v14)],
    targets: [
        .target(
            name: "TGWSProxyCore",
            path: "Sources/TGWSProxyCore"
        ),
        .executableTarget(
            name: "TGWSProxyMac",
            dependencies: ["TGWSProxyCore"],
            path: "Sources/TGWSProxyMac"
        ),
        .executableTarget(
            name: "TGWSProxyTest",
            dependencies: ["TGWSProxyCore"],
            path: "Sources/TGWSProxyTest"
        )
    ]
)
