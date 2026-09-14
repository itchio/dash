package dash

// Reference game pages used to verify this detector:
//   https://miracula-works.itch.io/orbital-scouter
//     Lua game, SDK 3.1.1
//   https://joyrider3774.itch.io/gamebuino-classic-sdl
//     C game with pdex.bin only, runs on device alone
//   https://shadowbreakgames.itch.io/skyline-test-pilot
//     C and Lua, with a Windows simulator plugin (pdex.dll)
//   https://aloebach.itch.io/pulp-game
//     Pulp export, SDK 1.10.0
//   https://tosiabunio.itch.io/robbo-for-playdate
//     pushed with butler
//   https://joyrider3774.itch.io/znax-playdate-windows-mac
//     C and Lua, SDK 3.0.5

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// playdateDetector emits every folder holding a pdxinfo file as a bundle
// the Playdate Simulator (or the device) runs. The folder is usually named
// <Game>.pdx; when it is not, a runnable file with the Playdate magic has
// to be present. main.pdz is the compiled Lua, pdex.bin the device image
// of a C game, and pdex.dll/dylib/so the same C code built for the
// simulator of one desktop OS. A C game without the plugin for the host
// cannot run in the host's simulator.
//
// Details: "bundleId", "name", "gameVersion", "buildNumber" from pdxinfo;
// "lua" (main.pdz present), "native" (pdex.bin present), "simulator"
// (which of "windows", "macos", "linux" have a plugin), "pulp" (made with
// Pulp), "confidence" ("ext" when only the folder name says so).
type playdateDetector struct{}

const (
	playdatePdzMagic = "Playdate PDZ"
	playdatePdxMagic = "Playdate PDX"
	// pdxinfo is a handful of short lines; anything past this is not one
	playdateInfoMax = 8192
)

func (playdateDetector) detect(s *scan) error {
	for _, index := range s.filesNamed("pdxinfo") {
		dir := parentDir(s.lowerFiles[index])
		info := &EngineInfo{Engine: EnginePlaydate}

		lua := playdateHasMagic(s, joinPath(dir, "main.pdz"), playdatePdzMagic)
		native := playdateHasMagic(s, joinPath(dir, "pdex.bin"), playdatePdxMagic)
		if !lua && !native {
			if !strings.HasSuffix(dir, ".pdx") {
				continue
			}
			info.detail("confidence", "ext")
		}
		info.detail("lua", lua).detail("native", native)

		var simulator []string
		for _, p := range []struct{ name, os string }{
			{"pdex.dll", "windows"},
			{"pdex.dylib", "macos"},
			{"pdex.so", "linux"},
		} {
			if s.hasFile(joinPath(dir, p.name)) {
				simulator = append(simulator, p.os)
			}
		}
		if len(simulator) > 0 {
			info.detail("simulator", simulator)
		}

		fields := parsePdxinfo(s.readHead(index, playdateInfoMax))
		for key, detailKey := range map[string]string{
			"bundleID":    "bundleId",
			"name":        "name",
			"version":     "gameVersion",
			"buildNumber": "buildNumber",
		} {
			if v, ok := fields[key]; ok {
				info.detail(detailKey, v)
			}
		}
		if strings.HasPrefix(fields["bundleID"], "pulp.") {
			info.detail("pulp", true)
		}
		info.Version = playdateSDKVersion(fields["pdxversion"])

		s.addDirCandidate(s.originalDir(dir), FlavorPlaydatePdx, info)
	}
	return nil
}

func playdateHasMagic(s *scan, lowerPath string, magic string) bool {
	index, ok := s.file(lowerPath)
	if !ok {
		return false
	}
	return bytes.HasPrefix(s.readHead(index, len(magic)), []byte(magic))
}

// parsePdxinfo reads the key=value lines of a pdxinfo file.
func parsePdxinfo(buf []byte) map[string]string {
	fields := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(buf))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return fields
}

// playdateSDKVersion decodes pdxversion, which packs the SDK version as
// major*10000 + minor*100 + patch: 30101 is 3.1.1, 11000 is 1.10.0.
func playdateSDKVersion(pdxversion string) string {
	n, err := strconv.Atoi(pdxversion)
	if err != nil || n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", n/10000, n/100%100, n%100)
}
