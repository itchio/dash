package dash

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// godotDetector finds .pck files and pcks embedded in executables.
//
// Details: "packFormat" (1 = Godot 3, 2 = Godot 4), "embedded" (true when
// the pck lives inside the executable).
type godotDetector struct{}

const godotPckHeader = 20

func (godotDetector) detect(s *scan) error {
	// standalone pck files, blacklisted by extension so never sniffed
	for _, index := range s.filesWithSuffix(".pck") {
		info := parseGodotPck(s.readHead(index, godotPckHeader))
		if info == nil {
			continue
		}
		s.addFileCandidate(index, FlavorGodotPck, info)

		// the export next to the pck shares its stem: game.exe + game.pck
		lower := s.lowerFiles[index]
		dir := parentDir(lower)
		pckStem := stem(lowerBase(lower))
		for _, c := range s.nativesIn(dir) {
			if stem(lowerBase(c.Path)) == pckStem {
				c.setEngine(cloneEngine(info))
			}
		}
		// macOS exports keep the pck in Contents/Resources
		if strings.HasSuffix(dir, "/contents/resources") {
			s.annotateAround(dir, info)
		}
	}

	// embedded: the executable ends with u64 pck size + "GDPC"
	for _, c := range append([]*Candidate(nil), s.candidates...) {
		switch c.Flavor {
		case FlavorNativeWindows, FlavorNativeLinux, FlavorNativeMacos:
		default:
			continue
		}
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		tail := s.readTail(index, 12)
		if tail == nil || string(tail[8:12]) != "GDPC" {
			continue
		}
		pckSize := int64(binary.LittleEndian.Uint64(tail[0:8]))
		start := c.Size - 12 - pckSize
		if pckSize <= 0 || start < 0 {
			continue
		}
		r, err := s.open(index)
		if err != nil {
			continue
		}
		info := parseGodotPck(r.readAt(start, godotPckHeader))
		if info == nil {
			continue
		}
		info.detail("embedded", true)
		c.setEngine(cloneEngine(info))
		pck := s.addFileCandidate(index, FlavorGodotPck, info)
		pck.Mode = c.Mode
	}
	return nil
}

func parseGodotPck(hdr []byte) *EngineInfo {
	if len(hdr) < godotPckHeader || string(hdr[0:4]) != "GDPC" {
		return nil
	}
	format := binary.LittleEndian.Uint32(hdr[4:8])
	major := binary.LittleEndian.Uint32(hdr[8:12])
	minor := binary.LittleEndian.Uint32(hdr[12:16])
	patch := binary.LittleEndian.Uint32(hdr[16:20])
	if format > 16 || major == 0 || major > 100 {
		return nil
	}
	info := &EngineInfo{
		Engine:  EngineGodot,
		Version: fmt.Sprintf("%d.%d.%d", major, minor, patch),
	}
	info.detail("packFormat", int(format))
	return info
}
