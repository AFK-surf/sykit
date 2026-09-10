#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror -Iinclude tests/node-auth.c -o "$tmp/node-auth"
"$tmp/node-auth"
echo 'Node authentication tests passed.'
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror -Iinclude tests/session-deadline.c -o "$tmp/session-deadline"
"$tmp/session-deadline"
python3 tests/session-tools.py
python3 tests/build.py
