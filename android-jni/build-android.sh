#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_dir="${1:-${script_dir}/../../android-client/app/src/main/assets/mst5-native}"
ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/opt/android-sdk/ndk/29.0.14206865}}"
toolchain="${ndk_root}/toolchains/llvm/prebuilt/linux-x86_64/bin"

if [[ ! -x "${toolchain}/aarch64-linux-android21-clang" ]]; then
  echo "Android NDK toolchain was not found under ${ndk_root}" >&2
  exit 1
fi

build_target() {
  local rust_target="$1"
  local android_abi="$2"
  local linker="$3"
  local linker_env="$4"
  rustup target add "${rust_target}"
  env "${linker_env}=${toolchain}/${linker}" \
    cargo build --manifest-path "${script_dir}/Cargo.toml" --release --target "${rust_target}"
  mkdir -p "${output_dir}/${android_abi}"
  cp "${script_dir}/target/${rust_target}/release/libmst5_android.so" \
    "${output_dir}/${android_abi}/libmst5_android.so"
  "${toolchain}/llvm-strip" --strip-unneeded \
    "${output_dir}/${android_abi}/libmst5_android.so"
}

build_target \
  aarch64-linux-android \
  arm64-v8a \
  aarch64-linux-android21-clang \
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER

build_target \
  armv7-linux-androideabi \
  armeabi-v7a \
  armv7a-linux-androideabi21-clang \
  CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER

echo "MST5 Android libraries written to ${output_dir}"
