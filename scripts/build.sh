#!/bin/sh
# Works with Docker and Podman; extract the scratch image without running it.
set -eu
cd "$(dirname "$0")/.."
mode=${1:-build}
case "$mode" in build|--check) ;; *) echo 'usage: scripts/build.sh [--check]' >&2; exit 2;; esac
engine=${CONTAINER_ENGINE:-docker}
tmp=$(mktemp -d)
container=
cleanup() {
    if [ -n "$container" ]; then "$engine" rm "$container" >/dev/null || :; fi
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# Verification must actually recompile, even when image layers are cached.
cache_flag=
[ "$mode" != --check ] || cache_flag=--no-cache
"$engine" build $cache_flag --platform linux/amd64 --target artifacts --iidfile "$tmp/image-id" .
# Bind extraction to this build, never a shared mutable tag.
image_id=$(cat "$tmp/image-id")
mkdir "$tmp/artifacts"
container=$("$engine" create --platform linux/amd64 --pull=never "$image_id" /unused)
"$engine" cp "$container:/artifacts/." "$tmp/artifacts/"
if [ "$mode" = --check ]; then
    diff -r objects "$tmp/artifacts"
else
    mkdir -p objects
    cp "$tmp/artifacts/"*.o "$tmp/artifacts/SHA256SUMS" objects/
fi
