package dash

// Reference game pages used to verify this detector:
//   https://nothke.itch.io/interminal
//     2019.4 il2cpp
//   https://nyxgaming.itch.io/first-time-caller
//     2020.1 mono
//   https://whalesandgames.itch.io/colossorama
//     Unity 5.4
//   https://agggron.itch.io/the-yellow-moon-inn
//     2017.3
//   https://raealbus.itch.io/culinary-cooking
//     WebGL

import (
	"regexp"
	"strings"
)

// unityDetector annotates Unity players. A Windows or Linux build has
// <name>_Data/ next to <name>.exe and UnityPlayer.dll/.so beside it; a
// macOS bundle has Contents/Resources/Data/ and UnityPlayer.dylib in
// Contents/Frameworks; a WebGL build has Build/ next to index.html with
// the loader script inside.
//
// Details: "scripting" ("il2cpp" or "mono"), "platform" ("webgl").
type unityDetector struct{}

var unityVersionPattern = regexp.MustCompile(`\d{1,4}\.\d+\.\d+[abfp]\d+`)

func (unityDetector) detect(s *scan) error {
	for _, c := range s.candidates {
		var dataDir, libDir string
		lower := strings.ToLower(c.Path)
		switch c.Flavor {
		case FlavorNativeWindows, FlavorNativeLinux:
			dir := parentDir(lower)
			dataDir = joinPath(dir, stem(lowerBase(lower))+"_data")
			libDir = dir
			if !s.hasDir(dataDir) {
				if !unityPlayerLibIn(s, dir) || strings.HasPrefix(lowerBase(lower), "unitycrashhandler") {
					continue
				}
				dataDir = anyUnityDataDir(s, dir)
			}
		case FlavorAppMacos:
			dataDir = lower + "/contents/resources/data"
			libDir = lower + "/contents/frameworks"
			if !s.hasDir(dataDir) && !unityPlayerLibIn(s, libDir) {
				continue
			}
		case FlavorHTML:
			if !unityWebGLIn(s, joinPath(parentDir(lower), "build")) {
				continue
			}
			info := &EngineInfo{Engine: EngineUnity}
			info.detail("platform", "webgl")
			c.setEngine(info)
			continue
		default:
			continue
		}
		c.setEngine(unityInfo(s, dataDir, libDir))
	}
	return nil
}

// unityWebGLIn looks for the loader in a Build/ folder: UnityLoader.js
// before 2020, <name>.loader.js since.
func unityWebGLIn(s *scan, buildDir string) bool {
	if !s.hasDir(buildDir) {
		return false
	}
	for _, lower := range s.lowerFiles {
		if parentDir(lower) != buildDir {
			continue
		}
		base := lowerBase(lower)
		if base == "unityloader.js" || strings.HasSuffix(base, ".loader.js") || strings.HasSuffix(base, ".wasm") || strings.HasSuffix(base, ".unityweb") {
			return true
		}
	}
	return false
}

func unityPlayerLibIn(s *scan, dir string) bool {
	for _, name := range []string{"unityplayer.dll", "unityplayer.so", "libunityplayer.so", "unityplayer.dylib"} {
		if s.hasFile(joinPath(dir, name)) {
			return true
		}
	}
	return false
}

// anyUnityDataDir finds a *_Data folder directly inside dir, for
// executables whose name does not match it (renamed launchers).
func anyUnityDataDir(s *scan, dir string) string {
	for d := range s.dirs {
		if parentDir(d) == dir && strings.HasSuffix(d, "_data") {
			return d
		}
	}
	return ""
}

func unityInfo(s *scan, dataDir, libDir string) *EngineInfo {
	info := &EngineInfo{Engine: EngineUnity}
	for _, name := range []string{"globalgamemanagers", "data.unity3d", "level0", "mainData"} {
		index, ok := s.file(joinPath(dataDir, strings.ToLower(name)))
		if !ok {
			continue
		}
		if m := unityVersionPattern.Find(s.readHead(index, 128)); m != nil {
			info.Version = string(m)
			break
		}
	}
	scripting := "mono"
	if s.hasDir(joinPath(dataDir, "il2cpp_data")) {
		scripting = "il2cpp"
	} else {
		for _, name := range []string{"gameassembly.dll", "gameassembly.so", "gameassembly.dylib"} {
			if s.hasFile(joinPath(libDir, name)) {
				scripting = "il2cpp"
				break
			}
		}
	}
	info.detail("scripting", scripting)
	return info
}
