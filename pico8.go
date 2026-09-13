package dash

// Reference game pages used to verify this detector:
//   https://cpav.itch.io/pocket-tactics
//     .p8.png
//   https://egordorichev.itch.io/penance
//     .p8 text cart, version 11
//   https://not-articulated.itch.io/urbanitas
//     Picotron .p64.png cart
//   https://noelcody.itch.io/moss-moss
//     .p8.png cart, and a web export with the cart embedded in its .js

import (
	"bytes"
	"regexp"
	"strings"
)

// pico8Detector finds PICO-8 and Picotron cartridges. The text forms (.p8,
// .p64) start with a "<name> cartridge" line; the .png forms hide the cart
// in pixel data and are trusted on their name alone. A PICO-8 web export
// carries the cart ROM as a byte array in its .js, so that file is a cart
// too, one a runner has to decode first.
//
// Details: "format" ("p8", "p64", "png", or "js" for a web export's
// script), "confidence" ("ext" for png carts), "carts" (how many 32 KiB
// carts a web export's array holds, when the array fit in the budget).
type pico8Detector struct{}

var pico8VersionPattern = regexp.MustCompile(`(?m)^version (\d+)`)
var pico8ShellPattern = regexp.MustCompile(`PICO-8 (\d+\.\d+(?:\.\d+)?)`)

const pico8CartSize = 32768

func (pico8Detector) detect(s *scan) error {
	for index, lower := range s.lowerFiles {
		switch {
		case strings.HasSuffix(lower, ".p8.png"):
			info := &EngineInfo{Engine: EnginePico8}
			info.detail("format", "png").detail("confidence", "ext")
			s.addFileCandidate(index, FlavorPico8Cart, info)
		case strings.HasSuffix(lower, ".p64.png"):
			info := &EngineInfo{Engine: EnginePicotron}
			info.detail("format", "png").detail("confidence", "ext")
			s.addFileCandidate(index, FlavorPicotronCart, info)
		case strings.HasSuffix(lower, ".p64"):
			if !bytes.HasPrefix(s.readHead(index, 128), []byte("picotron cartridge")) {
				continue
			}
			info := &EngineInfo{Engine: EnginePicotron}
			info.detail("format", "p64")
			s.addFileCandidate(index, FlavorPicotronCart, info)
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

	// web exports: index.html plus <name>.js holding "var _cartdat=[...]"
	for _, c := range append([]*Candidate(nil), s.candidates...) {
		if c.Flavor != FlavorHTML {
			continue
		}
		dir := parentDir(strings.ToLower(c.Path))
		htmlIndex, _ := s.file(strings.ToLower(c.Path))
		version := ""
		if m := pico8ShellPattern.FindSubmatch(s.readHead(htmlIndex, 2048)); m != nil {
			version = string(m[1])
		}
		for index, lower := range s.lowerFiles {
			if parentDir(lower) != dir || !strings.HasSuffix(lower, ".js") {
				continue
			}
			if !bytes.Contains(s.readHead(index, 256), []byte("var _cartdat=[")) {
				continue
			}
			info := &EngineInfo{Engine: EnginePico8, Version: version}
			info.detail("format", "js")
			if n := pico8CartCount(s, index); n > 0 {
				info.detail("carts", n)
			}
			s.addFileCandidate(index, FlavorPico8Cart, info)
		}
	}
	return nil
}

// pico8CartCount sizes the _cartdat array, which lists one decimal byte
// per cart byte. Returns 0 when the array does not end within what the
// budget allows reading.
func pico8CartCount(s *scan, index int) int {
	head := s.readHead(index, int(min(s.container.Files[index].Size, DefaultMaxProbeBytes)))
	start := bytes.Index(head, []byte("var _cartdat=["))
	if start < 0 {
		return 0
	}
	end := bytes.IndexByte(head[start:], ']')
	if end < 0 {
		return 0
	}
	array := head[start+len("var _cartdat=[") : start+end]
	values := bytes.Count(array, []byte(",")) + 1
	return values / pico8CartSize
}
