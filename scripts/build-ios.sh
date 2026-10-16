#!/usr/bin/env bash
# Builds MailflareCoreFFI.xcframework and regenerates the Swift bindings.
#   scripts/build-ios.sh            release (device + simulator)
#   scripts/build-ios.sh --debug    faster, unoptimized
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE=release
CARGO_FLAGS=(--release)
if [[ "${1:-}" == "--debug" ]]; then
	PROFILE=debug
	CARGO_FLAGS=()
fi

export IPHONEOS_DEPLOYMENT_TARGET=18.0
LIB=libmailflare_core.a
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)

for target in "${TARGETS[@]}"; do
	rustup target add "$target" >/dev/null
	cargo build --lib "${CARGO_FLAGS[@]}" --target "$target"
done

# Bindings come from the host build's metadata; they are target-independent.
cargo build --lib
BINDINGS=build/bindings
rm -rf "$BINDINGS"
cargo run --quiet --bin uniffi-bindgen -- generate --library target/debug/libmailflare_core.dylib \
	--language swift --out-dir "$BINDINGS"

HEADERS=build/headers
rm -rf "$HEADERS"
mkdir -p "$HEADERS"
cp "$BINDINGS"/mailflare_coreFFI.h "$HEADERS"/
cp "$BINDINGS"/mailflare_coreFFI.modulemap "$HEADERS"/module.modulemap
cp "$BINDINGS"/mailflare_core.swift swift/Sources/MailflareCore/mailflare_core.swift

SIM=build/ios-simulator
mkdir -p "$SIM"
lipo -create \
	"target/aarch64-apple-ios-sim/$PROFILE/$LIB" \
	"target/x86_64-apple-ios/$PROFILE/$LIB" \
	-output "$SIM/$LIB"

rm -rf build/MailflareCoreFFI.xcframework
xcodebuild -create-xcframework \
	-library "target/aarch64-apple-ios/$PROFILE/$LIB" -headers "$HEADERS" \
	-library "$SIM/$LIB" -headers "$HEADERS" \
	-output build/MailflareCoreFFI.xcframework >/dev/null

echo "Built build/MailflareCoreFFI.xcframework ($PROFILE)"
