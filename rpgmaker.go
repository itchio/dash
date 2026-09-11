package dash

// Reference game pages used to verify this detector:
//   https://qbk.itch.io/pdgrm2k3
//     RPG Maker 2003 with EasyRPG Player.exe
//   https://daturabane.itch.io/russian-roulette-simulator-2003
//     RPG Maker 2003
//   https://nomnomnami.itch.io/lonely-wolf-treat
//     VX Ace, Game.ini with RGSS301
//   MV/MZ builds: not yet verified against a live game

import (
	"regexp"
	"strings"
)

// rpgmakerDetector covers three generations, each its own flavor:
//
//   - rpgmaker-mv: folder with js/rpg_core.js (MV) or js/rmmz_core.js (MZ),
//     Details "variant" mv/mz, version from Utils.RPGMAKER_VERSION
//   - rpgmaker-xp: folder with Game.ini and an RGSS archive or Data/
//     folder, Details "variant" xp/vx/vxace, version is the RGSS major
//   - rpgmaker-2k: folder with RPG_RT.ldb
type rpgmakerDetector struct{}

var rpgmakerMVVersionPattern = regexp.MustCompile(`RPGMAKER_VERSION\s*=\s*"([^"]+)"`)
var rpgmakerLibraryPattern = regexp.MustCompile(`(?i)Library\s*=\s*RGSS(\d)`)

func (rpgmakerDetector) detect(s *scan) error {
	for index, lower := range s.lowerFiles {
		base := lowerBase(lower)
		dir := parentDir(lower)
		switch base {
		case "rpg_core.js", "rmmz_core.js":
			if lowerBase(dir) != "js" {
				continue
			}
			root := parentDir(dir)
			variant := "mv"
			if base == "rmmz_core.js" {
				variant = "mz"
			}
			info := &EngineInfo{Engine: EngineRPGMaker}
			info.detail("variant", variant)
			if m := rpgmakerMVVersionPattern.FindSubmatch(s.readHead(index, 16<<10)); m != nil {
				info.Version = string(m[1])
			}
			s.addDirCandidate(s.originalDir(root), FlavorRPGMakerMV, info)
			if html := s.candidateAt(joinPath(root, "index.html")); html != nil {
				html.setEngine(cloneEngine(info))
			}
			// nw.js shells sit next to www/ or next to index.html
			s.annotateNativesIn(root, info)
			if lowerBase(root) == "www" {
				s.annotateNativesIn(parentDir(root), info)
			}

		case "game.ini":
			variant, version := rpgmakerXPVariant(s, index, dir)
			if variant == "" {
				continue
			}
			info := &EngineInfo{Engine: EngineRPGMaker, Version: version}
			info.detail("variant", variant)
			s.addDirCandidate(s.originalDir(dir), FlavorRPGMakerXP, info)
			s.annotateNativesIn(dir, info)

		case "rpg_rt.ldb":
			info := &EngineInfo{Engine: EngineRPGMaker}
			info.detail("variant", "2k")
			s.addDirCandidate(s.originalDir(dir), FlavorRPGMaker2k, info)
			s.annotateNativesIn(dir, info)
		}
	}
	return nil
}

// rpgmakerXPVariant tells XP, VX and VX Ace apart by the RGSS library
// named in Game.ini, falling back to the archive or data file extension.
func rpgmakerXPVariant(s *scan, iniIndex int, dir string) (variant string, version string) {
	ini := s.readHead(iniIndex, 4096)
	if m := rpgmakerLibraryPattern.FindSubmatch(ini); m != nil {
		switch string(m[1]) {
		case "1":
			return "xp", "1"
		case "2":
			return "vx", "2"
		case "3":
			return "vxace", "3"
		}
	}
	for _, lower := range s.lowerFiles {
		if parentDir(lower) != dir && parentDir(parentDir(lower)) != dir {
			continue
		}
		switch getExt(lower) {
		case ".rgssad", ".rxdata":
			return "xp", "1"
		case ".rgss2a", ".rvdata":
			return "vx", "2"
		case ".rgss3a", ".rvdata2":
			return "vxace", "3"
		}
	}
	// a Game.ini without RGSS traces is some other game's settings file
	if !s.hasFile(joinPath(dir, "game.exe")) || !strings.Contains(strings.ToLower(string(ini)), "rgss") {
		return "", ""
	}
	return "xp", ""
}
