package dash

// Reference game pages used to verify this detector:
//   https://glowingdawnmist.itch.io/nanobot
//     .solarus archive
//   the folder form: not yet verified against a live game

import (
	"regexp"
	"strings"
)

// solarusDetector finds quests: .solarus archives (a zip with quest.dat at
// its root) and folders holding data/quest.dat.
type solarusDetector struct{}

var solarusVersionPattern = regexp.MustCompile(`solarus_version\s*=\s*"([^"]+)"`)

func solarusInfo(questDat []byte) *EngineInfo {
	info := &EngineInfo{Engine: EngineSolarus}
	if m := solarusVersionPattern.FindSubmatch(questDat); m != nil {
		info.Version = string(m[1])
	}
	return info
}

func (solarusDetector) detect(s *scan) error {
	for index, lower := range s.lowerFiles {
		switch {
		case strings.HasSuffix(lower, ".solarus"):
			r, err := s.open(index)
			if err != nil {
				continue
			}
			zr := openZip(r)
			if zr == nil {
				continue
			}
			entry := zipEntry(zr, "quest.dat", true)
			if entry == nil {
				continue
			}
			s.addFileCandidate(index, FlavorSolarusQuest, solarusInfo(zipReadEntry(entry, 16<<10)))

		case strings.HasSuffix(lower, "/data/quest.dat") || lower == "data/quest.dat":
			root := parentDir(parentDir(lower))
			info := solarusInfo(s.readHead(index, 16<<10))
			s.addDirCandidate(s.originalDir(root), FlavorSolarusQuest, info)
			s.annotateNativesIn(root, info)
		}
	}
	return nil
}
