package dash

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// swfDetector finds Flash movies and projector executables. A projector is
// the player with the movie appended and a marker + size as the last 8
// bytes; the exe is emitted as a payload since Ruffle can load it.
//
// Details: "projector" (true for executables).
type swfDetector struct{}

const swfProjectorMarker = 0xfa123456

func swfInfo(head []byte) *EngineInfo {
	if len(head) < 4 {
		return nil
	}
	switch string(head[0:3]) {
	case "FWS", "CWS", "ZWS":
	default:
		return nil
	}
	return &EngineInfo{Engine: EngineFlash, Version: strconv.Itoa(int(head[3]))}
}

func (swfDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".swf") {
		info := swfInfo(s.readHead(index, 4))
		if info == nil {
			continue
		}
		s.addFileCandidate(index, FlavorSWF, info)
	}

	for _, c := range append([]*Candidate(nil), s.candidates...) {
		if c.Flavor != FlavorNativeWindows {
			continue
		}
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		tail := s.readTail(index, 8)
		if tail == nil || binary.LittleEndian.Uint32(tail[0:4]) != swfProjectorMarker {
			continue
		}
		swfSize := int64(binary.LittleEndian.Uint32(tail[4:8]))
		start := c.Size - 8 - swfSize
		if swfSize <= 0 || start < 0 {
			continue
		}
		r, err := s.open(index)
		if err != nil {
			continue
		}
		info := swfInfo(r.readAt(start, 4))
		if info == nil {
			continue
		}
		info.detail("projector", true)
		c.setEngine(cloneEngine(info))
		p := s.addFileCandidate(index, FlavorSWF, info)
		p.Mode = c.Mode
	}
	return nil
}
