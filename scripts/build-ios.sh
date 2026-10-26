#!/usr/bin/env bash
# Builds MailflareCoreFFI.xcframework and regenerates the Swift bindings.
#   scripts/build-ios.sh            release (device + simulator)
#   scripts/build-ios.sh --debug    faster, unoptimized
#   scripts/build-ios.sh --macos    also adds a universal macOS slice (for mailflare-macos)
# Flags combine, e.g. `scripts/build-ios.sh --debug --macos`.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE=release
CARGO_FLAGS=(--release)
WITH_MACOS=0
for arg in "$@"; do
	case "$arg" in
		--debug) PROFILE=debug; CARGO_FLAGS=() ;;
		--macos) WITH_MACOS=1 ;;
		*) echo "unknown flag: $arg" >&2; exit 2 ;;
	esac
done

export IPHONEOS_DEPLOYMENT_TARGET=18.0
LIB=libmailflare_core.a
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)

for target in "${TARGETS[@]}"; do
	rustup target add "$target" >/dev/null
	cargo build --lib ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"} --target "$target"
done

MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
if [[ "$WITH_MACOS" == 1 ]]; then
	export MACOSX_DEPLOYMENT_TARGET=14.0
	for target in "${MACOS_TARGETS[@]}"; do
		rustup target add "$target" >/dev/null
		cargo build --lib ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"} --target "$target"
	done
fi

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

SLICES=(
	-library "target/aarch64-apple-ios/$PROFILE/$LIB" -headers "$HEADERS"
	-library "$SIM/$LIB" -headers "$HEADERS"
)
if [[ "$WITH_MACOS" == 1 ]]; then
	MAC=build/macos
	mkdir -p "$MAC"
	lipo -create \
		"target/aarch64-apple-darwin/$PROFILE/$LIB" \
		"target/x86_64-apple-darwin/$PROFILE/$LIB" \
		-output "$MAC/$LIB"
	SLICES+=(-library "$MAC/$LIB" -headers "$HEADERS")
fi

rm -rf build/MailflareCoreFFI.xcframework
xcodebuild -create-xcframework "${SLICES[@]}" -output build/MailflareCoreFFI.xcframework >/dev/null

echo "Built build/MailflareCoreFFI.xcframework ($PROFILE)"
