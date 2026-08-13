#!/usr/bin/env bash
set -euo pipefail

target="${1:?target is required}"
label="${2:?artifact label is required}"
profile="${PROFILE:-release}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${root}/Cargo.toml" | head -n1)"
source_dir="${root}/ffi/target/${target}/${profile}"
out="${root}/dist/${label}"
mkdir -p "$out/include" "$out/lib"
cp "$root/ffi/include/mst5.h" "$out/include/"

found=0
for candidate in \
	"$source_dir/libmst5_client_ffi.so" \
	"$source_dir/libmst5_client_ffi.dylib" \
	"$source_dir/libmst5_client_ffi.a" \
	"$source_dir/mst5_client_ffi.dll" \
	"$source_dir/mst5_client_ffi.dll.lib"; do
	if [[ -f "$candidate" ]]; then cp "$candidate" "$out/lib/"; found=1; fi
done
[[ "$found" == 1 ]] || { echo "no native library found in $source_dir" >&2; exit 1; }
cp "$root/LICENSE-MIT" "$root/LICENSE-APACHE" "$out/" 2>/dev/null || true
printf '{"abi":1,"version":"%s","target":"%s"}\n' "$version" "$target" > "$out/manifest.json"
(cd "$root/dist" && tar -czf "mst5-client-${version}-${label}.tar.gz" "$label")
