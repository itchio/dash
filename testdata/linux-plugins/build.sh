#!/bin/sh
# Tiny aarch64 ELF files, built without libc, that are ET_DYN for different
# reasons: plugins loaded by another program, a position independent
# executable, and a static-pie. Needs aarch64-linux-gnu-gcc.
set -e
cd "$(dirname "$0")"
CC="aarch64-linux-gnu-gcc -nostdlib -Wl,-z,max-page-size=0x1000 -Wl,-z,noseparate-code"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo 'int SDL_Init(unsigned f) { return (int)f; }' >"$tmp/lib.c"
$CC -shared -Wl,-soname,libSDL2-2.0.so.0 -o "$tmp/libSDL2-2.0.so.0" "$tmp/lib.c"

# a node addon and a CLAP plugin: shared objects with dependencies and no
# program interpreter, under extensions the library name pattern misses
echo 'int napi_register_module_v1(void) { return 0; }' >"$tmp/addon.c"
$CC -shared -o greenworks.node "$tmp/addon.c" -Wl,--no-as-needed "$tmp/libSDL2-2.0.so.0"
cp greenworks.node synth.clap

# a position independent executable: ET_DYN with a program interpreter
echo 'void _start(void) { for (;;) {} }' >"$tmp/main.c"
$CC -fPIE -pie -Wl,-e,_start -o game "$tmp/main.c" -Wl,--no-as-needed "$tmp/libSDL2-2.0.so.0"

# a static-pie: ET_DYN with neither interpreter nor dependencies
$CC -fPIE -static-pie -Wl,-e,_start -o game-static-pie "$tmp/main.c"

# split debug info as Unity ships next to its player
aarch64-linux-gnu-objcopy --only-keep-debug game game_s.debug
ls -la
