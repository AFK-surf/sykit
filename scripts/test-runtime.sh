#!/bin/sh
# Reuse upstream's runtime harness and dependencies without maintaining a fork.
set -eu
cd "$(dirname "$0")/.."
export SYKIT_ROOT="$PWD"
checkout=${1:?usage: scripts/test-runtime.sh /path/to/synchronicity}
checkout=$(cd "$checkout" && pwd)
test_file="$checkout/crates/synch-sock/tests/sykit_artifacts.rs"
# Atomically refuse existing files, including dangling symlinks.
if ! (set -C; cat tests/runtime.rs > "$test_file"); then
    echo "Could not exclusively create $test_file" >&2
    exit 1
fi
trap 'rm -f "$test_file"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$checkout"
cargo test -p synch-sock --test sykit_artifacts
