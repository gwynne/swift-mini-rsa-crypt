// swift-tools-version:5.4
import PackageDescription

let development = false

let swiftSettings: [SwiftSetting]
let dependencies: [Target.Dependency]
if development {
    dependencies = [
        "CMiniRSACryptBoringSSL",
        "CMiniRSACryptBoringSSLShims"
    ]
} else {
    let platforms: [Platform] = [
        Platform.linux,
        Platform.android,
        Platform.windows,
    ]
    dependencies = [
        .target(name: "CMiniRSACryptBoringSSL", condition: .when(platforms: platforms)),
        .target(name: "CMiniRSACryptBoringSSLShims", condition: .when(platforms: platforms))
    ]
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
    dependencies: [],
    targets: [
        .target(
            name: "CMiniRSACryptBoringSSL",
            exclude: [
                "hash.txt",
                "include/boringssl_prefix_symbols_nasm.inc",
            ],
            cSettings: [
                /*
                 * This define is required on Windows, but because we need older
                 * versions of SPM, we cannot conditionally define this on Windows
                 * only.  Unconditionally define it instead.
                 */
                .define("WIN32_LEAN_AND_MEAN"),
            ]
        ),
        .target(
            name: "CMiniRSACryptBoringSSLShims",
            dependencies: ["CMiniRSACryptBoringSSL"]
        ),
        .target(
            name: "MiniRSACrypt",
            dependencies: dependencies
            ),
        .testTarget(name: "MiniRSACryptTests", dependencies: ["MiniRSACrypt"]),
    ],
    cxxLanguageStandard: .cxx11
)
