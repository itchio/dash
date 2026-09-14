package dash

// A Verdict contains a wealth of information on how to "launch" or "open" a specific
// folder.
type Verdict struct {
	// BasePath is the absolute path of the folder that was configured
	BasePath string `json:"basePath"`
	// TotalSize is the size in bytes of the folder and all its children, recursively
	TotalSize int64 `json:"totalSize"`
	// Candidates is a list of potentially interesting files, with a lot of additional info
	Candidates []*Candidate `json:"candidates"`
}

// A Candidate is a potentially interesting launch target, be it
// a native executable, a Java or Love2D bundle, an HTML index, etc.
type Candidate struct {
	// Path is relative to the configured folder
	Path string `json:"path"`
	// Mode describes file permissions
	Mode uint32 `json:"mode,omitempty"`
	// Depth is the number of path elements leading up to this candidate
	Depth int `json:"depth"`
	// Flavor is the type of a candidate - native, html, jar etc.
	Flavor Flavor `json:"flavor"`
	// Arch describes the architecture of a candidate (where relevant)
	Arch Arch `json:"arch,omitempty"`
	// Size is the size of the candidate's file, in bytes
	Size int64 `json:"size"`
	// Spell contains raw output from <https://github.com/itchio/wizardry>
	// @optional
	Spell []string `json:"spell,omitempty"`
	// WindowsInfo contains information specific to native Windows candidates
	// @optional
	WindowsInfo *WindowsInfo `json:"windowsInfo,omitempty"`
	// LinuxInfo contains information specific to native Linux candidates
	// @optional
	LinuxInfo *LinuxInfo `json:"linuxInfo,omitempty"`
	// MacosInfo contains information specific to native macOS candidates
	// @optional
	MacosInfo *MacosInfo `json:"macosInfo,omitempty"`
	// LoveInfo contains information specific to Love2D bundles (`.love` files)
	// @optional
	LoveInfo *LoveInfo `json:"loveInfo,omitempty"`
	// ScriptInfo contains information specific to shell scripts (`.sh`, `.bat` etc.)
	// @optional
	ScriptInfo *ScriptInfo `json:"scriptInfo,omitempty"`
	// JarInfo contains information specific to Java archives (`.jar` files)
	// @optional
	JarInfo *JarInfo `json:"jarInfo,omitempty"`
	// Engine is what made this candidate. Set on natives when a known engine
	// left its footprint next to them, and on payload flavors always.
	// @optional
	Engine *EngineInfo `json:"engine,omitempty"`
	// Any other info.
	// @optional
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Flavor describes whether we're dealing with a native executables, a Java archive, a love2d bundle, etc.
type Flavor string

const (
	// FlavorNativeLinux denotes native linux executables
	FlavorNativeLinux Flavor = "linux"
	// ExecNativeMacos denotes native macOS executables
	FlavorNativeMacos Flavor = "macos"
	// FlavorPe denotes native windows executables
	FlavorNativeWindows Flavor = "windows"
	// FlavorAppMacos denotes a macOS app bundle
	FlavorAppMacos Flavor = "app-macos"
	// FlavorScript denotes scripts starting with a shebang (#!)
	FlavorScript Flavor = "script"
	// FlavorScriptWindows denotes windows scripts (.bat or .cmd)
	FlavorScriptWindows Flavor = "windows-script"
	// FlavorJar denotes a .jar archive with a Main-Class
	FlavorJar Flavor = "jar"
	// FlavorHTML denotes an index html file
	FlavorHTML Flavor = "html"
	// FlavorLove denotes a love package
	FlavorLove Flavor = "love"
	// Microsoft installer packages
	FlavorMSI Flavor = "msi"

	// Payload flavors: files or folders an external runtime consumes.
	// Every candidate with one of these carries an Engine.

	// Godot pack file, standalone or embedded in an executable
	FlavorGodotPck Flavor = "godot-pck"
	// GameMaker data file (data.win, game.unx, game.ios, game.droid)
	FlavorGameMakerData Flavor = "gamemaker-data"
	// PICO-8 cartridge (.p8, .p8.png)
	FlavorPico8Cart Flavor = "pico8-cart"
	// Picotron cartridge (.p64, .p64.png)
	FlavorPicotronCart Flavor = "picotron-cart"
	// Ren'Py project: the folder holding game/
	FlavorRenpy Flavor = "renpy"
	// RPG Maker MV/MZ project: the folder holding js/ and index.html
	FlavorRPGMakerMV Flavor = "rpgmaker-mv"
	// RPG Maker XP/VX/VX Ace project: the folder holding Game.ini
	FlavorRPGMakerXP Flavor = "rpgmaker-xp"
	// RPG Maker 2000/2003 project: the folder holding RPG_RT.ldb
	FlavorRPGMaker2k Flavor = "rpgmaker-2k"
	// Adventure Game Studio game: the exe with appended data, or a .ags file
	FlavorAGS Flavor = "ags"
	// Doom engine WAD or PK3
	FlavorDoomWad Flavor = "doom-wad"
	// Flash movie, standalone or in a projector exe
	FlavorSWF Flavor = "swf"
	// Folder holding 16-bit DOS executables
	FlavorDOS Flavor = "dos"
	// Pyxel application bundle (.pyxapp)
	FlavorPyxelApp Flavor = "pyxel-app"
	// Solarus quest (.solarus archive or folder holding data/quest.dat)
	FlavorSolarusQuest Flavor = "solarus-quest"
	// TIC-80 cartridge (.tic)
	FlavorTIC80Cart Flavor = "tic80-cart"
	// OpenBOR module (.pak)
	FlavorOpenBORPak Flavor = "openbor-pak"
	// Console ROM or disc image, system in Engine.Details["system"]
	FlavorROM Flavor = "rom"
	// Playdate game bundle: the folder holding pdxinfo
	FlavorPlaydatePdx Flavor = "playdate-pdx"
)

// The architecture of an executable
type Arch string

const (
	// 32-bit
	Arch386 Arch = "386"
	// 64-bit
	ArchAmd64 Arch = "amd64"
	// ARM 64-bit (Apple Silicon, aarch64 handhelds)
	ArchArm64 Arch = "arm64"
	// ARM 32-bit (Raspberry Pi and older handhelds)
	ArchArm Arch = "arm"
	// RISC-V 64-bit
	ArchRiscv64 Arch = "riscv64"
	// Universal binary (multiple architectures)
	ArchUniversal Arch = "universal"
)

// HasMacosArch reports whether a macOS candidate can run natively on the
// given architecture, looking inside universal binaries.
func (c *Candidate) HasMacosArch(arch Arch) bool {
	if c.Arch == arch {
		return true
	}
	if c.MacosInfo == nil {
		return false
	}
	for _, a := range c.MacosInfo.Architectures {
		if a == arch {
			return true
		}
	}
	return false
}

// Contains information specific to native windows executables
// or installer packages.
type WindowsInfo struct {
	// Particular type of installer (msi, inno, etc.)
	// @optional
	InstallerType WindowsInstallerType `json:"installerType,omitempty"`
	// True if we suspect this might be an uninstaller rather than an installer
	// @optional
	Uninstaller bool `json:"uninstaller,omitempty"`
	// Is this executable marked as GUI? This can be false and still pop a GUI, it's just a hint.
	// @optional
	Gui bool `json:"gui,omitempty"`
	// Is this a .NET assembly?
	// @optional
	DotNet bool `json:"dotNet,omitempty"`
	// Machine type from the PE header
	// @optional
	Arch Arch `json:"arch,omitempty"`
	// Imported DLLs, only filled when ConfigureParams.DeepProbe is set
	// @optional
	Imports []string `json:"imports,omitempty"`
	// Strings from the VS_VERSIONINFO resource (ProductName, FileVersion,
	// CompanyName, ...). Only filled when ConfigureParams.DeepProbe is set.
	// @optional
	VersionProperties map[string]string `json:"versionProperties,omitempty"`
	// requestedExecutionLevel from the embedded manifest ("asInvoker",
	// "requireAdministrator", "highestAvailable"). Only filled when
	// ConfigureParams.DeepProbe is set.
	// @optional
	RequestedExecutionLevel string `json:"requestedExecutionLevel,omitempty"`
}

// Which particular type of windows-specific installer
type WindowsInstallerType string

const (
	// Microsoft install packages (`.msi` files)
	WindowsInstallerTypeMsi WindowsInstallerType = "msi"
	// InnoSetup installers
	WindowsInstallerTypeInno WindowsInstallerType = "inno"
	// NSIS installers
	WindowsInstallerTypeNullsoft WindowsInstallerType = "nsis"
	// Self-extracting installers that 7-zip knows how to extract
	WindowsInstallerTypeArchive WindowsInstallerType = "archive"
)

// Contains information specific to native macOS executables
// or app bundles.
type MacosInfo struct {
	// All CPU architectures found in the binary (for universal/fat binaries)
	// @optional
	Architectures []Arch `json:"architectures,omitempty"`
}

// Contains information specific to native Linux executables
type LinuxInfo struct {
	// Machine type from the ELF header
	// @optional
	Arch Arch `json:"arch,omitempty"`
	// Operating system the ELF targets when it is not Linux: "freebsd",
	// "openbsd", "netbsd" from the header's OS ABI byte, "haiku" from its
	// imports (deep probe only). Such builds still get the linux flavor.
	// @optional
	OS string `json:"os,omitempty"`
	// Calling convention for 32-bit ARM, from the ELF header flags:
	// "eabihf" (hard-float, what Raspberry Pi and armhf distributions
	// build) or "eabi" (soft-float). Empty for other architectures.
	// @optional
	ABI string `json:"abi,omitempty"`
	// Program interpreter (PT_INTERP), such as /lib/ld-linux-armhf.so.3
	// or /lib/ld-musl-aarch64.so.1. Names the C library and ABI the
	// executable was linked against. Only filled when DeepProbe is set.
	// @optional
	Interpreter string `json:"interpreter,omitempty"`
	// True when the executable has no dynamic section (no interpreter, no
	// DT_NEEDED). Only meaningful when ConfigureParams.DeepProbe is set.
	// @optional
	Static bool `json:"static,omitempty"`
	// Highest GLIBC_x.y symbol version the executable references.
	// Only filled when ConfigureParams.DeepProbe is set.
	// @optional
	GlibcVersion string `json:"glibcVersion,omitempty"`
	// Shared libraries listed in DT_NEEDED, in link order.
	// Only filled when ConfigureParams.DeepProbe is set.
	// @optional
	Imports []string `json:"imports,omitempty"`
	// SDL major version the executable uses, "2" or "3": imported, or
	// linked in (see SDLBundled). Only filled when DeepProbe is set.
	// @optional
	SDL string `json:"sdl,omitempty"`
	// True when SDL is linked into the executable rather than imported,
	// so it only has the display backends it was built with.
	// @optional
	SDLBundled bool `json:"sdlBundled,omitempty"`
	// True when a bundled SDL kept its dynamic API, the hook that lets a
	// host substitute its own SDL at load time (SDL_DYNAMIC_API).
	// @optional
	SDLDynamicAPI bool `json:"sdlDynamicApi,omitempty"`
	// Windowing and graphics libraries the executable, or the SDL it
	// bundles, can load: "x11", "wayland", "kmsdrm", "glfw", "egl", "gl",
	// "gles", "vulkan". From DT_NEEDED and the library names it carries
	// for dlopen. Only filled when DeepProbe is set.
	// @optional
	Display []string `json:"display,omitempty"`
	// True when the executable keeps its symbol table.
	// Only filled when DeepProbe is set.
	// @optional
	Symbols bool `json:"symbols,omitempty"`
}

// Contains information specific to Love2D bundles
type LoveInfo struct {
	// The version of love2D required to open this bundle. May be empty
	// @optional
	Version string `json:"version,omitempty"`
}

// Contains information specific to shell scripts
type ScriptInfo struct {
	// Something like `/bin/bash`
	// @optional
	Interpreter string `json:"interpreter,omitempty"`
}

// Contains information specific to Java archives
type JarInfo struct {
	// The main Java class as specified by the manifest included in the .jar (if any)
	// @optional
	MainClass string `json:"mainClass,omitempty"`
}
