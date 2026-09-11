package dash

import (
	"bytes"
	"regexp"
	"strings"
)

// pico8Detector finds cartridges. .p8 is text with a version line; .p8.png
// hides the cart in pixel data and is trusted on its name alone.
//
// Details: "format" ("p8" or "png"), "confidence" ("ext" for png carts).
type pico8Detector struct{}

var pico8VersionPattern = regexp.MustCompile(`(?m)^version (\d+)`)

func (pico8Detector) detect(s *scan) error {
	for index, lower := range s.lowerFiles {
		switch {
		case strings.HasSuffix(lower, ".p8.png"):
			info := &EngineInfo{Engine: EnginePico8}
			info.detail("format", "png").detail("confidence", "ext")
			s.addFileCandidate(index, FlavorPico8Cart, info)
		case strings.HasSuffix(lower, ".p8"):
			head := s.readHead(index, 128)
			if !bytes.HasPrefix(head, []byte("pico-8 cartridge")) {
				continue
			}
			info := &EngineInfo{Engine: EnginePico8}
			info.detail("format", "p8")
			if m := pico8VersionPattern.FindSubmatch(head); m != nil {
				info.Version = string(m[1])
			}
			s.addFileCandidate(index, FlavorPico8Cart, info)
		}
	}
	return nil
}
