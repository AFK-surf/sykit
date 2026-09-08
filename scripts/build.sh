#!/bin/sh
# Works with Docker and Podman; extract the scratch image without running it.
set -eu
cd "$(dirname "$0")/.."
mode=${1:-build}
case "$mode" in build|--check) ;; *) echo 'usage: scripts/build.sh [--check]' >&2; exit 2;; esac
engine=${CONTAINER_ENGINE:-docker}
tmp=$(mktemp -d)
container=
trap '[ -z "$container" ] || "$engine" rm "$container" >/dev/null; rm -rf "$tmp"' EXIT HUP INT TERM
# Verification must actually recompile, even when image layers are cached.
cache_flag=
[ "$mode" != --check ] || cache_flag=--no-cache
"$engine" build $cache_flag --platform linux/amd64 --target artifacts -t sykit-artifacts .
container=$("$engine" create --platform linux/amd64 sykit-artifacts /unused)
"$engine" cp "$container:/." "$tmp/"
if [ "$mode" = --check ]; then
    diff -r objects "$tmp"
else
    mkdir -p objects
    cp "$tmp/"*.o "$tmp/SHA256SUMS" objects/
fi
