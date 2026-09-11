package dash

import (
	"encoding/binary"
	"fmt"
)

// gamemakerDetector finds GameMaker data files and annotates the runner
// next to them.
//
// Details: "bytecode" (14 = GMS 1.4, 15/16 = GMS 2.x, 17 = 2.3+).
//
// GEN8 layout follows UndertaleModTool's UndertaleGeneralInfo. GameMaker
// Studio 2 and later leave the runtime version fields at 2.0.0.0, so only
// the major is reported when the rest are zero.
type gamemakerDetector struct{}

var gamemakerDataNames = map[string]bool{
	"data.win":   true,
	"game.unx":   true,
	"game.ios":   true,
	"game.droid": true,
}

func (gamemakerDetector) detect(s *scan) error {
	for index, lower := range s.lowerFiles {
		if !gamemakerDataNames[lowerBase(lower)] {
			continue
		}
		info := parseGameMakerGEN8(s.readHead(index, 76))
		if info == nil {
			continue
		}
		s.addFileCandidate(index, FlavorGameMakerData, info)

		// Windows: Game.exe next to data.win. Linux: runner next to
		// assets/game.unx.
		dir := parentDir(lower)
		s.annotateAround(dir, info)
		if lowerBase(dir) == "assets" {
			s.annotateNativesIn(parentDir(dir), info)
		}
	}
	return nil
}

func parseGameMakerGEN8(head []byte) *EngineInfo {
	if len(head) < 76 || string(head[0:4]) != "FORM" || string(head[8:12]) != "GEN8" {
		return nil
	}
	body := head[16:]
	bytecode := int(body[1])
	major := binary.LittleEndian.Uint32(body[44:48])
	minor := binary.LittleEndian.Uint32(body[48:52])
	release := binary.LittleEndian.Uint32(body[52:56])
	build := binary.LittleEndian.Uint32(body[56:60])

	info := &EngineInfo{Engine: EngineGameMaker}
	switch {
	case major == 0 || major >= 10000:
	case minor == 0 && release == 0 && build == 0:
		info.Version = fmt.Sprintf("%d", major)
	default:
		info.Version = fmt.Sprintf("%d.%d.%d.%d", major, minor, release, build)
	}
	info.detail("bytecode", bytecode)
	return info
}
