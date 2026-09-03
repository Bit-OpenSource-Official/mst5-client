#!/usr/bin/env sh
# Produce the versioned browser package consumed by messenger-clients/web-client.
# The Rust build script deliberately requires CRYPT_SERVER_PUBLIC_KEY_B64, so a
# browser artifact can never accidentally be published without the transport pin.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:-"$root/mst5-client-wasm.tar.gz"}
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)

if [ -z "$version" ] || [ -z "${CRYPT_SERVER_PUBLIC_KEY_B64:-}" ]; then
    echo "CRYPT_SERVER_PUBLIC_KEY_B64 and a WASM package version are required" >&2
    exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/mst5-wasm.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

CC=${CC:-clang} AR=${AR:-llvm-ar} wasm-pack build "$root" --release --target web --out-dir "$work/wasm"
printf '{"abi":1,"version":"%s","target":"wasm32-unknown-unknown","format":"web-esm"}\n' "$version" \
    > "$work/wasm/manifest.json"
mkdir -p "$(dirname -- "$output")"
tar -C "$work" -czf "$output" wasm
echo "Wrote $output (mst5-client WASM $version)"
