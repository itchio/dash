package dash

// I know what you're thinking.
//
// You're thinking: I love amos and all, but he's being kinda dumb right now -
// why not just use a whitelist? You'd put ".exe", ".sh", and a handful of
// others and - voilà! You'd only sniff files that could potentially be
// launchable.
//
// And the terrible truth is: that's what this code was, until a blessed unit
// test reminded me that Linux/macOS binaries can be named *darn well anything*.
// Not just "diceydungeons" but also "Game.x86_64".
//
// And if your whitelist doesn't have ".x86_64", well then you're out of luck,
// aren't you?
//
// So, now, it's a blacklist with the file extensions we're *pretty damn sure*
// aren't executables.
//
// TL;DR - an incomplete whitelist means we miss the thing we need to launch and NOTHING works.
// An incomplete blacklist just slows us down a little, and can always be completed later.
var fileExtBlacklist map[string]struct{} = map[string]struct{}{
	".bmp":  struct{}{},
	".tga":  struct{}{},
	".png":  struct{}{},
	".gif":  struct{}{},
	".jpg":  struct{}{},
	".jpeg": struct{}{},

	// electron bundles
	".asar": struct{}{},

	// audio
	".ogg": struct{}{},
	".wav": struct{}{},
	".mp3": struct{}{},

	// video
	".mp4": struct{}{},
	".mpg": struct{}{},
	".avi": struct{}{},

	// source files
	".js":  struct{}{},
	".py":  struct{}{},
	".rb":  struct{}{},
	".go":  struct{}{},
	".c":   struct{}{},
	".h":   struct{}{},
	".c++": struct{}{},
	".cxx": struct{}{},
	".cpp": struct{}{},

	// structured data
	".json": struct{}{},
	".xml":  struct{}{},

	// UE4 assets
	".pak": struct{}{},

	// libraries
	".dll":   struct{}{},
	".so":    struct{}{},
	".dylib": struct{}{},

	// fonts
	".otf":        struct{}{},
	".ttf":        struct{}{},
	".packedfont": struct{}{},

	// ?? found in opus magnum
	".cso":  struct{}{},
	".glsl": struct{}{},
	".out":  struct{}{},

	// ffs @queenjazz
	".roobos": struct{}{},

	// macOS crap
	".ds_store": struct{}{},

	// databases
	".db":     struct{}{},
	".sql":    struct{}{},
	".sqlite": struct{}{},

	// various
	".txt":    struct{}{},
	".ini":    struct{}{},
	".conf":   struct{}{},
	".config": struct{}{},
	".cfg":    struct{}{},
	".dat":    struct{}{},
	".map":    struct{}{},
}
