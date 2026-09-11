package dash

// Reference game pages used to verify this detector:
//   https://rtheilade.itch.io/monogame-zombie-repeat-shooter
//     MonoGame on Linux, .NET core
//   https://joppiesaus.itch.io/offensive-defense
//     MonoGame on Windows, .NET framework
//   FNA and XNA: not yet verified against a live game

import (
	"strings"
)

// dotnetDetector annotates FNA, MonoGame and XNA games by the framework
// assembly next to the executable.
//
// Details: "dotnet" ("core" when a *.runtimeconfig.json is present, else
// "framework", which Mono can run).
type dotnetDetector struct{}

func (dotnetDetector) detect(s *scan) error {
	cache := make(map[string]*EngineInfo)
	for _, c := range s.candidates {
		if !c.IsNative() || c.Flavor == FlavorAppMacos {
			continue
		}
		dir := parentDir(strings.ToLower(c.Path))
		info, ok := cache[dir]
		if !ok {
			info = dotnetInfo(s, dir)
			cache[dir] = info
		}
		if info != nil {
			c.setEngine(cloneEngine(info))
		}
	}
	return nil
}

func dotnetInfo(s *scan, dir string) *EngineInfo {
	var engine Engine
	core := false
	for _, lower := range s.lowerFiles {
		if parentDir(lower) != dir {
			continue
		}
		base := lowerBase(lower)
		switch {
		case base == "fna.dll":
			engine = EngineFNA
		case strings.HasPrefix(base, "monogame.framework") && strings.HasSuffix(base, ".dll"):
			if engine == "" {
				engine = EngineMonoGame
			}
		case strings.HasPrefix(base, "microsoft.xna.framework") && strings.HasSuffix(base, ".dll"):
			if engine == "" {
				engine = EngineXNA
			}
		case strings.HasSuffix(base, ".runtimeconfig.json"):
			core = true
		}
	}
	if engine == "" {
		return nil
	}
	info := &EngineInfo{Engine: engine}
	if core {
		info.detail("dotnet", "core")
	} else {
		info.detail("dotnet", "framework")
	}
	return info
}
