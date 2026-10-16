// swift-tools-version: 6.0
// The iOS app consumes the core as this local package. Run
// `scripts/build-ios.sh` first: it builds the XCFramework into build/ and
// regenerates the UniFFI bindings in swift/Sources/MailflareCore.
import PackageDescription

let package = Package(
	name: "MailflareCore",
	platforms: [.iOS(.v18)],
	products: [
		.library(name: "MailflareCore", targets: ["MailflareCore"]),
	],
	targets: [
		.binaryTarget(name: "mailflare_coreFFI", path: "build/MailflareCoreFFI.xcframework"),
		.target(
			name: "MailflareCore",
			dependencies: ["mailflare_coreFFI"],
			path: "swift/Sources/MailflareCore"
		),
	]
)
