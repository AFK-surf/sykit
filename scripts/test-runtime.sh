#!/bin/sh
# Reuse upstream's runtime harness and dependencies without maintaining a fork.
set -eu
cd "$(dirname "$0")/.."
export SYKIT_ROOT="$PWD"
checkout=${1:?usage: scripts/test-runtime.sh /path/to/synchronicity}
checkout=$(cd "$checkout" && pwd)
test_file="$checkout/crates/synch-sock/tests/sykit_artifacts.rs"
if [ -e "$test_file" ]; then
    echo "Refusing to overwrite $test_file" >&2
    exit 1
fi
trap 'rm -f "$test_file"' EXIT HUP INT TERM
cp tests/runtime.rs "$test_file"
cd "$checkout"
cargo test -p synch-sock --test sykit_artifacts
