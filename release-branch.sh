#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	echo "Usage: make release-branch X.Y.Z" >&2
	exit 2
fi

version="$1"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$root"

[[ "$(git branch --show-current)" == main ]] || { echo "error: releases must be published from main" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "error: working tree is not clean" >&2; exit 1; }
crate_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
ffi_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' ffi/Cargo.toml | head -n 1)"
[[ "$crate_version" == "$version" && "$ffi_version" == "$version" ]] || {
	echo "error: branch version $version must match mst5-client ($crate_version) and ffi ($ffi_version)" >&2
	exit 1
}

git fetch --quiet origin "+refs/heads/main:refs/remotes/origin/main"
git merge-base --is-ancestor origin/main main || { echo "error: main is behind or diverged from origin/main" >&2; exit 1; }
branch="release/$version"
if git ls-remote --exit-code --heads origin "refs/heads/$branch" >/dev/null 2>&1; then
	git fetch --quiet origin "+refs/heads/$branch:refs/remotes/origin/$branch"
	git merge-base --is-ancestor "origin/$branch" main || { echo "error: origin/$branch cannot be fast-forwarded" >&2; exit 1; }
fi
git push origin "HEAD:refs/heads/$branch"
echo "Published current main to origin/$branch; local branch remains main."
