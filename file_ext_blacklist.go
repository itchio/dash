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
	// images
	".atf":  struct{}{}, // adobe texture format
	".xcf":  struct{}{}, // gimp
	".psd":  struct{}{}, // photoshop
	".ico":  struct{}{}, // windows icons
	".icns": struct{}{}, // macOS icons
	".bmp":  struct{}{}, // bitmaps
	".tga":  struct{}{}, // targa
	".png":  struct{}{},
	".gif":  struct{}{},
	".jpg":  struct{}{},
	".jpeg": struct{}{},

	".asar": struct{}{}, // electron bundles

	// audio
	".ogg": struct{}{},
	".wav": struct{}{},
	".mp3": struct{}{},
	".vox": struct{}{}, // voice something?
	".bnk": struct{}{}, // sound banks?

	// video
	".mp4":  struct{}{},
	".mpg":  struct{}{},
	".avi":  struct{}{},
	".aspx": struct{}{},

	// levels
	".lvl": struct{}{},
	".tmx": struct{}{},

	// source files
	".tsx":  struct{}{},
	".ts":   struct{}{},
	".jsx":  struct{}{},
	".js":   struct{}{},
	".is":   struct{}{},
	".rb":   struct{}{},
	".go":   struct{}{},
	".c":    struct{}{},
	".h":    struct{}{},
	".c++":  struct{}{},
	".cxx":  struct{}{},
	".cpp":  struct{}{},
	".moon": struct{}{},
	".hx":   struct{}{},
	".vbs":  struct{}{},
	".pxi":  struct{}{},

	// python garbo
	".py":    struct{}{},
	".pyo":   struct{}{},
	".pyd":   struct{}{},
	".pyx":   struct{}{},
	".rpy":   struct{}{},
	".rpyc":  struct{}{},
	".rpym":  struct{}{},
	".rpymc": struct{}{},
	".egg":   struct{}{},

	// structured data
	".json": struct{}{},
	".xml":  struct{}{},
	".csv":  struct{}{},

	// unknown
	".pck":      struct{}{},
	".assets":   struct{}{},
	".asset":    struct{}{},
	".sav":      struct{}{},
	".wem":      struct{}{},
	".browser":  struct{}{},
	".resource": struct{}{},
	".ress":     struct{}{},
	".chr":      struct{}{},
	".rpa":      struct{}{},
	".pxd":      struct{}{},
	".exr":      struct{}{},

	// debug symbols
	".pdb": struct{}{},
	".mdb": struct{}{},

	// UE4 assets
	".pak": struct{}{},

	// libraries
	".dll":   struct{}{},
	".ndll":  struct{}{}, // Haxe/Neko stuff
	".so":    struct{}{},
	".dylib": struct{}{},

	// fonts
	".fnt":        struct{}{},
	".otf":        struct{}{},
	".ttf":        struct{}{},
	".packedfont": struct{}{},

	// ?? found in opus magnum
	".cso": struct{}{},

	// shaders
	".glsl": struct{}{},

	// ffs @queenjazz
	".roobos": struct{}{},

	// macOS crap
	".ds_store": struct{}{},
	".plist":    struct{}{},

	// databases
	".db":     struct{}{},
	".sql":    struct{}{},
	".sqlite": struct{}{},

	// various
	".txt":      struct{}{},
	".ini":      struct{}{},
	".conf":     struct{}{},
	".config":   struct{}{},
	".cfg":      struct{}{},
	".dat":      struct{}{},
	".map":      struct{}{},
	".out":      struct{}{},
	".solution": struct{}{},
	".info":     struct{}{},

	// flash
	".swf": struct{}{},
}