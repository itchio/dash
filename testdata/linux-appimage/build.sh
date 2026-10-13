#!/bin/sh
# An AppImage beside its unpacked tree, as a host without FUSE lays it out.
# Tiny aarch64 executables built without libc; needs aarch64-linux-gnu-gcc.
set -e
cd "$(dirname "$0")"
CC="aarch64-linux-gnu-gcc -nostdlib -Wl,-e,_start -Wl,-z,max-page-size=0x1000 -Wl,-z,noseparate-code"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# the fixture lives in root/ so this script is not a candidate of its own
mkdir -p root && cd root
mkdir -p Game.AppImage.d/usr/bin Game.AppImage.d/usr/lib

# the shipped SDL names its backends; the game only imports it
cat >"$tmp/sdl.c" <<'C'
const char *const strings[] = {"SDL_VIDEODRIVER", "libX11.so.6", "libgbm.so.1"};
int SDL_Init(unsigned f) { return (int)f; }
C
aarch64-linux-gnu-gcc -nostdlib -shared -Wl,-soname,libSDL2-2.0.so.0 -o Game.AppImage.d/usr/lib/libSDL2-2.0.so.0.3000.0 "$tmp/sdl.c"
echo 'void _start(void) { for (;;) {} }' >"$tmp/main.c"
$CC -o Game.AppImage.d/usr/bin/game "$tmp/main.c" -Wl,--no-as-needed Game.AppImage.d/usr/lib/libSDL2-2.0.so.0.3000.0

# the runtime stub: a static executable with the AppImage mark in e_ident
$CC -o Game.AppImage -static "$tmp/main.c"
printf 'AI\002' | dd of=Game.AppImage bs=1 seek=8 conv=notrunc 2>/dev/null

printf '#!/bin/sh\nexec "${0%%/*}/usr/bin/game" "$@"\n' > Game.AppImage.d/AppRun
chmod +x Game.AppImage Game.AppImage.d/AppRun Game.AppImage.d/usr/bin/game

# the same image unpacked with AppRun as a symlink to the game
cd .. && rm -rf linked && cp -r root linked
ln -sf usr/bin/game linked/Game.AppImage.d/AppRun
ls -laR
