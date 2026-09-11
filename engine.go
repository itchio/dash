package dash

// Engine identifies the tool a game was made with. It is the key a consumer
// uses to pick a runtime: a native candidate carries it as extra context, a
// payload candidate carries it because the payload is nothing without it.
type Engine string

const (
	EngineGodot     Engine = "godot"
	EngineUnity     Engine = "unity"
	EngineUnreal    Engine = "unreal"
	EngineGameMaker Engine = "gamemaker"
	EngineLove      Engine = "love"
	EnginePico8     Engine = "pico8"
	EnginePicotron  Engine = "picotron"
	EngineRenpy     Engine = "renpy"
	EngineRPGMaker  Engine = "rpgmaker"
	EngineAGS       Engine = "ags"
	EngineDoom      Engine = "doom"
	EngineFlash     Engine = "flash"
	EngineDOS       Engine = "dos"
	EnginePyxel     Engine = "pyxel"
	EngineSolarus   Engine = "solarus"
	EngineTIC80     Engine = "tic80"
	EngineOpenBOR   Engine = "openbor"
	// ROM images: the console lives in Details["system"]
	EngineROM       Engine = "rom"
	EngineFNA       Engine = "fna"
	EngineMonoGame  Engine = "monogame"
	EngineXNA       Engine = "xna"
	EngineHashLink  Engine = "hashlink"
	EngineDefold    Engine = "defold"
	EngineConstruct Engine = "construct"
	EngineElectron  Engine = "electron"
	EngineNWJS      Engine = "nwjs"
	EnginePython    Engine = "python"
	EngineLibGDX    Engine = "libgdx"
	EngineLWJGL     Engine = "lwjgl"
)

// EngineInfo describes what made a candidate and, for payloads, what runtime
// it needs.
type EngineInfo struct {
	Engine Engine `json:"engine"`
	// Engine version, in the engine's own notation: "3.5.2", "2022.3.10f1",
	// "11.5". Empty when it would cost too much to find out or is not
	// recorded anywhere.
	// @optional
	Version string `json:"version,omitempty"`
	// Free-form engine facts. Keys are documented per detector; the ones
	// shared across engines are "confidence" ("ext" when only the file name
	// was used) and "system" (console id for ROMs).
	// @optional
	Details map[string]any `json:"details,omitempty"`
}

func (e *EngineInfo) detail(key string, value any) *EngineInfo {
	if e.Details == nil {
		e.Details = make(map[string]any)
	}
	e.Details[key] = value
	return e
}

// setEngine annotates a candidate, keeping an existing annotation unless
// it is for the same engine and lacks a version the new one has.
func (c *Candidate) setEngine(info *EngineInfo) {
	if info == nil {
		return
	}
	if c.Engine == nil {
		c.Engine = info
		return
	}
	if c.Engine.Engine == info.Engine && c.Engine.Version == "" {
		c.Engine.Version = info.Version
		for k, v := range info.Details {
			if _, ok := c.Engine.Details[k]; !ok {
				c.Engine.detail(k, v)
			}
		}
	}
}

// PayloadFlavors lists every flavor that is a data file or folder some
// external runtime consumes, as opposed to something the host execs.
var PayloadFlavors = []Flavor{
	FlavorJar,
	FlavorHTML,
	FlavorLove,
	FlavorGodotPck,
	FlavorGameMakerData,
	FlavorPico8Cart,
	FlavorPicotronCart,
	FlavorRenpy,
	FlavorRPGMakerMV,
	FlavorRPGMakerXP,
	FlavorRPGMaker2k,
	FlavorAGS,
	FlavorDoomWad,
	FlavorSWF,
	FlavorDOS,
	FlavorPyxelApp,
	FlavorSolarusQuest,
	FlavorTIC80Cart,
	FlavorOpenBORPak,
	FlavorROM,
}

// enginePayloadFlavors are the payload flavors introduced with engine
// detection. Filter ranks them below html and above jar, see Verdict.Filter.
var enginePayloadFlavors = map[Flavor]bool{
	FlavorGodotPck:      true,
	FlavorGameMakerData: true,
	FlavorPico8Cart:     true,
	FlavorPicotronCart:  true,
	FlavorRenpy:         true,
	FlavorRPGMakerMV:    true,
	FlavorRPGMakerXP:    true,
	FlavorRPGMaker2k:    true,
	FlavorAGS:           true,
	FlavorDoomWad:       true,
	FlavorSWF:           true,
	FlavorDOS:           true,
	FlavorPyxelApp:      true,
	FlavorSolarusQuest:  true,
	FlavorTIC80Cart:     true,
	FlavorOpenBORPak:    true,
	FlavorROM:           true,
}

// IsPayload reports whether a candidate needs an external runtime.
func (c *Candidate) IsPayload() bool {
	for _, f := range PayloadFlavors {
		if c.Flavor == f {
			return true
		}
	}
	return false
}

// IsNative reports whether a candidate is something a host OS can exec
// directly (including scripts and app bundles).
func (c *Candidate) IsNative() bool {
	switch c.Flavor {
	case FlavorNativeLinux, FlavorNativeWindows, FlavorNativeMacos, FlavorAppMacos, FlavorScript, FlavorScriptWindows:
		return true
	}
	return false
}
