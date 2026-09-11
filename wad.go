package dash

import (
	"strings"
)

// wadDetector finds Doom engine data: IWAD/PWAD files and PK3 archives
// that carry map or script definitions.
//
// Details: "wadType" ("iwad" or "pwad"), "format" ("wad" or "pk3").
type wadDetector struct{}

func (wadDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".wad") {
		head := s.readHead(index, 4)
		var wadType string
		switch string(head) {
		case "IWAD":
			wadType = "iwad"
		case "PWAD":
			wadType = "pwad"
		default:
			continue
		}
		info := &EngineInfo{Engine: EngineDoom}
		info.detail("format", "wad").detail("wadType", wadType)
		s.addFileCandidate(index, FlavorDoomWad, info)
	}

	for _, index := range s.filesWithSuffix(".pk3") {
		r, err := s.open(index)
		if err != nil {
			continue
		}
		zr := openZip(r)
		if zr == nil {
			continue
		}
		found := false
		for _, f := range zr.File {
			name := strings.ToLower(zipEntryPath(f.Name))
			name = stem(name)
			switch name {
			case "mapinfo", "zmapinfo", "umapinfo", "emapinfo", "zscript", "decorate":
				found = true
			}
			if found {
				break
			}
		}
		if !found {
			continue
		}
		info := &EngineInfo{Engine: EngineDoom}
		info.detail("format", "pk3").detail("wadType", "pwad")
		s.addFileCandidate(index, FlavorDoomWad, info)
	}
	return nil
}
