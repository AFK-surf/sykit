#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
${CC:-cc} -std=c11 -O2 -Wall -Wextra -Werror -Iinclude tests/node-auth.c -o "$tmp/node-auth"
"$tmp/node-auth"
echo 'Node authentication tests passed.'
