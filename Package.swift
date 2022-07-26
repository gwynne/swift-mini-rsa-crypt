// swift-tools-version:5.4
import PackageDescription

let development = true

let condition: TargetDependencyCondition?
if development {
    condition = nil
} else {
    condition = .when(platforms: [.linux, .android, .windows])
}

let package = Package(
    name: "swift-mini-rsa-crypt",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(name: "MiniRSACrypt", targets: ["MiniRSACrypt"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CMiniRSACryptBoringSSL", type: .static, targets: ["CMiniRSACryptBoringSSL"]),
            MANGLE_END */
    ],
    targets: [
        .target(
            name: "CMiniRSACryptBoringSSL",
            exclude: ["hash.txt", "include/boringssl_prefix_symbols_nasm.inc"],
            cSettings: [.define("WIN32_LEAN_AND_MEAN")]
        ),
        .target(
            name: "CMiniRSACryptBoringSSLShims",
            dependencies: [.target(name: "CMiniRSACryptBoringSSL")]
        )
        ,
        .target(
            name: "MiniRSACrypt",
            dependencies: [
                .target(name: "CMiniRSACryptBoringSSL", condition: condition),
                .target(name: "CMiniRSACryptBoringSSLShims", condition: condition),
            ]
        ),
        
        .testTarget(
            name: "MiniRSACryptTests",
            dependencies: [
                .target(name: "MiniRSACrypt"),
            ]
        ),
    ],
    cxxLanguageStandard: .cxx11
)
