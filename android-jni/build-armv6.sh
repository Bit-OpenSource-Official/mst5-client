#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_dir="${1:-${script_dir}/../../android-client/app/src/main/assets/mst5-native}"
cabi_output_dir="${2:-}"
ndk_root="${ANDROID_NDK_R14_HOME:-}"
toolchain="${ARMV6_ANDROID_TOOLCHAIN:-${script_dir}/target/android-api9-arm-toolchain}"
target_dir="${CARGO_TARGET_DIR:-${script_dir}/target}"

if [[ -z "${ndk_root}" || ! -f "${ndk_root}/build/tools/make_standalone_toolchain.py" ]]; then
  echo "Set ANDROID_NDK_R14_HOME to an extracted Android NDK r14b directory." >&2
  exit 1
fi

if [[ ! -x "${toolchain}/bin/arm-linux-androideabi-gcc" ]]; then
  python3 "${ndk_root}/build/tools/make_standalone_toolchain.py" \
    --arch arm \
    --api 9 \
    --install-dir "${toolchain}"
fi

rustup target add arm-linux-androideabi --toolchain nightly
rustup component add rust-src --toolchain nightly

unwind_dir="${ndk_root}/sources/cxx-stl/llvm-libc++/libs/armeabi"
armv6_cflags="${CFLAGS_arm_linux_androideabi:-} -std=gnu99"
env \
  CC_arm_linux_androideabi="${toolchain}/bin/arm-linux-androideabi-gcc" \
  AR_arm_linux_androideabi="${toolchain}/bin/arm-linux-androideabi-ar" \
  CFLAGS_arm_linux_androideabi="${armv6_cflags}" \
  CARGO_TARGET_ARM_LINUX_ANDROIDEABI_LINKER="${toolchain}/bin/arm-linux-androideabi-gcc" \
  CARGO_PROFILE_RELEASE_PANIC=abort \
  RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=arm1176jzf-s -C panic=abort -L native=${unwind_dir}" \
  rustup run nightly cargo -Z build-std=std,panic_abort build \
    --manifest-path "${script_dir}/Cargo.toml" \
    --target-dir "${target_dir}" \
    --no-default-features \
    --release \
    --target arm-linux-androideabi

mkdir -p "${output_dir}/armeabi"
cp "${target_dir}/arm-linux-androideabi/release/libmst5_android.so" \
  "${output_dir}/armeabi/libmst5_android.so"
"${toolchain}/bin/arm-linux-androideabi-strip" --strip-unneeded \
  "${output_dir}/armeabi/libmst5_android.so"

if ! "${toolchain}/bin/arm-linux-androideabi-readelf" -A \
    "${output_dir}/armeabi/libmst5_android.so" | grep -q 'Tag_CPU_arch: v6'; then
  echo "Refusing to publish a library that is not marked ARMv6." >&2
  exit 1
fi

echo "MST5 ARMv6/API 9 library written to ${output_dir}/armeabi"

if [[ -n "${cabi_output_dir}" ]]; then
  env \
    CC_arm_linux_androideabi="${toolchain}/bin/arm-linux-androideabi-gcc" \
    AR_arm_linux_androideabi="${toolchain}/bin/arm-linux-androideabi-ar" \
    CFLAGS_arm_linux_androideabi="${armv6_cflags}" \
    CARGO_TARGET_ARM_LINUX_ANDROIDEABI_LINKER="${toolchain}/bin/arm-linux-androideabi-gcc" \
    CARGO_PROFILE_RELEASE_PANIC=abort \
    RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=arm1176jzf-s -C panic=abort -L native=${unwind_dir}" \
    rustup run nightly cargo -Z build-std=std,panic_abort build \
      --manifest-path "${script_dir}/../ffi/Cargo.toml" \
      --target-dir "${target_dir}" \
      --no-default-features \
      --release \
      --target arm-linux-androideabi
  mkdir -p "${cabi_output_dir}/armeabi"
  cp "${target_dir}/arm-linux-androideabi/release/libmst5_client_ffi.so" \
    "${cabi_output_dir}/armeabi/libmst5_client_ffi.so"
  "${toolchain}/bin/arm-linux-androideabi-strip" --strip-unneeded \
    "${cabi_output_dir}/armeabi/libmst5_client_ffi.so"
fi
