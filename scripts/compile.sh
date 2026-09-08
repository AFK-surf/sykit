#!/bin/sh
set -eu
if [ "$(uname -m)" != x86_64 ]; then
    echo "Compilation requires an amd64 host; use scripts/build.sh." >&2
    exit 1
fi
out=${1:?usage: compile.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
for source in src/*.c; do
    name=$(basename "$source" .c)
    clang-18 -target bpfel -mcpu=v3 -std=c11 -O2 -g0 \
        -Wall -Wextra -Werror -fno-builtin \
        -ffile-prefix-map=/build=. -fdebug-prefix-map=/build=. \
        -mllvm -inline-threshold=2000000 \
        -mllvm -inline-cold-callsite-threshold=2000000 \
        -mllvm -bpf-stack-size=16384 \
        -Iinclude -c "$source" -o "$out/$name.o"
done
(cd "$out" && sha256sum ./*.o > SHA256SUMS)
