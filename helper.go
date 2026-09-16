package dash

// Reference game pages used to verify this detector:
//   https://noelcody.itch.io/moss-moss
//     zsync and python next to a Ren'Py launcher
//   https://metroid-studios.itch.io/dank-wizards
//     chrome_crashpad_handler and chrome-sandbox next to an Electron shell

import (
	"strings"
)

// helperDetector marks natives that are runtime plumbing rather than a
// launcher: crash handlers, sandboxes, updaters, bundled interpreters.
// They stay in the verdict with Helper set so a consumer can see what the
// upload ships, and Filter leaves them out. It runs after the engine
// detectors because some rules only apply inside a known engine's tree.
type helperDetector struct{}

// helperRule matches a native by its lowercased base name without .exe,
// optionally only when the candidate carries the given engine.
type helperRule struct {
	engine Engine
	names  []string
	helper string
}

var helperRules = []helperRule{
	{EngineRenpy, []string{"python", "pythonw", "python3", "zsync", "zsyncmake"}, "renpy"},
	{EngineElectron, []string{"chrome_crashpad_handler", "crashpad_handler", "chrome-sandbox"}, "electron"},
	{EngineNWJS, []string{"chrome_crashpad_handler", "crashpad_handler", "chrome-sandbox"}, "nwjs"},
	{"", []string{"chrome_crashpad_handler", "crashpad_handler", "chrome-sandbox"}, "chromium"},
	{"", []string{"nacl_helper", "nacl_helper_bootstrap", "nwjc", "payload"}, "nwjs"},
	{"", []string{"createdump"}, "dotnet"},
	{"", []string{"unitycrashhandler32", "unitycrashhandler64"}, "unity"},
	{"", []string{"crashreportclient", "unrealcefsubprocess", "ue4prereqsetup_x64", "ue4prereqsetup_x86", "ueprereqsetup_x64"}, "unreal"},
}

func (helperDetector) detect(s *scan) error {
	for _, c := range s.candidates {
		if !c.IsNative() || c.Flavor == FlavorAppMacos {
			continue
		}
		lower := strings.ToLower(c.Path)
		if helper := helperFor(s, c, lower); helper != "" {
			c.Helper = helper
		}
	}
	return nil
}

func helperFor(s *scan, c *Candidate, lower string) string {
	if strings.Contains("/"+lower, "/node_modules/") {
		return "node"
	}
	if isBundledJRE(s, lower) {
		return "java"
	}

	base := strings.TrimSuffix(lowerBase(lower), ".exe")
	var engine Engine
	if c.Engine != nil {
		engine = c.Engine.Engine
	}
	for _, rule := range helperRules {
		if rule.engine != "" && rule.engine != engine {
			continue
		}
		for _, name := range rule.names {
			if base == name {
				return rule.helper
			}
		}
	}
	return ""
}

// isBundledJRE reports whether a native sits in the bin/ of a Java runtime,
// which every JDK and JRE marks with a release file next to lib/.
func isBundledJRE(s *scan, lower string) bool {
	bin := parentDir(lower)
	if lowerBase(bin) != "bin" {
		return false
	}
	root := parentDir(bin)
	return s.hasFile(joinPath(root, "release")) && s.hasDir(joinPath(root, "lib"))
}
