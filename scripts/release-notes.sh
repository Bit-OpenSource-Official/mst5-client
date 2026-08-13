#!/usr/bin/env bash
set -euo pipefail

version="${1:?version is required}"
output="${2:?output file is required}"
repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
base="https://github.com/${repository}/releases/download/v${version}"

link() {
	local label="$1"
	local artifact="$2"
	printf '[%s](%s/%s)' "$label" "$base" "$artifact"
}

linux_gnu_x86="$(link 'скачать' "mst5-client-${version}-i686-unknown-linux-gnu.tar.gz")"
linux_gnu_x64="$(link 'скачать' "mst5-client-${version}-x86_64-unknown-linux-gnu.tar.gz")"
linux_gnu_arm6="$(link 'скачать' "mst5-client-${version}-arm-unknown-linux-gnueabi.tar.gz")"
linux_gnu_arm7="$(link 'скачать' "mst5-client-${version}-armv7-unknown-linux-gnueabihf.tar.gz")"
linux_gnu_arm64="$(link 'скачать' "mst5-client-${version}-aarch64-unknown-linux-gnu.tar.gz")"
linux_gnu_riscv="$(link 'скачать' "mst5-client-${version}-riscv64gc-unknown-linux-gnu.tar.gz")"
linux_musl_x86="$(link 'скачать' "mst5-client-${version}-i686-unknown-linux-musl.tar.gz")"
linux_musl_x64="$(link 'скачать' "mst5-client-${version}-x86_64-unknown-linux-musl.tar.gz")"
linux_musl_arm6="$(link 'скачать' "mst5-client-${version}-arm-unknown-linux-musleabi.tar.gz")"
linux_musl_arm7="$(link 'скачать' "mst5-client-${version}-armv7-unknown-linux-musleabihf.tar.gz")"
linux_musl_arm64="$(link 'скачать' "mst5-client-${version}-aarch64-unknown-linux-musl.tar.gz")"
linux_musl_riscv="$(link 'скачать' "mst5-client-${version}-riscv64gc-unknown-linux-musl.tar.gz")"
windows_x86="$(link 'скачать' "mst5-client-${version}-i686-pc-windows-msvc.tar.gz")"
windows_x64="$(link 'скачать' "mst5-client-${version}-x86_64-pc-windows-msvc.tar.gz")"
windows_arm64="$(link 'скачать' "mst5-client-${version}-aarch64-pc-windows-msvc.tar.gz")"
mac_x64="$(link 'скачать' "mst5-client-${version}-x86_64-apple-darwin.tar.gz")"
mac_arm64="$(link 'скачать' "mst5-client-${version}-aarch64-apple-darwin.tar.gz")"
ios_x64="$(link 'simulator' "mst5-client-${version}-x86_64-apple-ios.tar.gz")"
ios_arm64="$(link 'device' "mst5-client-${version}-aarch64-apple-ios.tar.gz") / $(link 'simulator' "mst5-client-${version}-aarch64-apple-ios-sim.tar.gz")"
android_arm6="$(link 'скачать' "mst5-client-${version}-android-armv6.tar.gz")"
android_arm7="$(link 'скачать' "mst5-client-${version}-android-armv7.tar.gz")"
android_arm64="$(link 'скачать' "mst5-client-${version}-android-arm64.tar.gz")"
android_x64="$(link 'скачать' "mst5-client-${version}-android-x86_64.tar.gz")"
mac_universal="$(link 'macOS universal' "mst5-client-${version}-macos-universal.tar.gz")"
apple_xcframework="$(link 'Apple XCFramework' "mst5-client-${version}-apple-xcframework.zip")"

cat > "$output" <<EOF
## Загрузки

| Платформа | x86 | x86_64 | ARMv6 | ARMv7 | ARM64 | RISC-V64 |
|---|---|---|---|---|---|---|
| Linux glibc | ${linux_gnu_x86} | ${linux_gnu_x64} | ${linux_gnu_arm6} | ${linux_gnu_arm7} | ${linux_gnu_arm64} | ${linux_gnu_riscv} |
| Linux musl | ${linux_musl_x86} | ${linux_musl_x64} | ${linux_musl_arm6} | ${linux_musl_arm7} | ${linux_musl_arm64} | ${linux_musl_riscv} |
| Windows | ${windows_x86} | ${windows_x64} | — | — | ${windows_arm64} | — |
| macOS | — | ${mac_x64} | — | — | ${mac_arm64} | — |
| iOS | — | ${ios_x64} | — | — | ${ios_arm64} | — |
| Android | — | ${android_x64} | ${android_arm6} | ${android_arm7} | ${android_arm64} | — |

Архивы из таблицы содержат C-заголовок, нативную библиотеку и manifest.json. Контрольные суммы находятся в [SHA256SUMS](${base}/SHA256SUMS).

Готовые объединённые пакеты: ${mac_universal}, ${apple_xcframework}.
EOF
