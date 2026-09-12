#!/bin/sh
# Tiny aarch64 executables for the windowing probe, built without libc so
# they stay a few KB. Needs aarch64-linux-gnu-gcc.
set -e
cd "$(dirname "$0")"
CC="aarch64-linux-gnu-gcc -nostdlib -Wl,-e,_start -Wl,-z,max-page-size=0x1000 -Wl,-z,noseparate-code -o"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# bundled SDL2 with the dynamic API kept, and X11/Wayland/KMSDRM backends
cat >"$tmp/static.c" <<'C'
const char *const strings[] = {"SDL_DYNAMIC_API", "SDL_VIDEODRIVER", "libX11.so.6",
                               "libwayland-client.so.0", "libdrm.so.2", "libgbm.so.1", "libEGL.so.1"};
int SDL_Init(unsigned f) { return (int)f; }
void _start(void) { for (;;) {} }
C
$CC sdl2-bundled -static "$tmp/static.c"
cp sdl2-bundled sdl2-bundled-stripped && aarch64-linux-gnu-strip sdl2-bundled-stripped

# the same SDL2 with the dynamic API compiled out
cat >"$tmp/fixed.c" <<'C'
const char *const strings[] = {"SDL_VIDEODRIVER", "libX11.so.6", "libGL.so.1"};
void _start(void) { for (;;) {} }
C
$CC sdl2-bundled-fixed -static "$tmp/fixed.c"

# bundled SDL3
cat >"$tmp/sdl3.c" <<'C'
const char *const strings[] = {"SDL3_DYNAMIC_API", "SDL_VIDEO_DRIVER", "libwayland-client.so.0"};
void _start(void) { for (;;) {} }
C
$CC sdl3-bundled -static "$tmp/sdl3.c"

# linked against the system's SDL2, and against GLFW with X11
echo 'int SDL_Init(unsigned f) { return (int)f; }' >"$tmp/lib.c"
for so in libSDL2-2.0.so.0 libglfw.so.3 libX11.so.6 libGL.so.1; do
    aarch64-linux-gnu-gcc -nostdlib -shared -Wl,-soname,$so -o "$tmp/$so" "$tmp/lib.c"
done
echo 'void _start(void) { for (;;) {} }' >"$tmp/main.c"
$CC sdl2-shared "$tmp/main.c" -Wl,--no-as-needed "$tmp/libSDL2-2.0.so.0"
$CC glfw-x11 "$tmp/main.c" -Wl,--no-as-needed "$tmp/libglfw.so.3" "$tmp/libX11.so.6" "$tmp/libGL.so.1"
ls -la
