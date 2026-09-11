package dash

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// agsDetector finds Adventure Game Studio games. The Windows build is the
// engine with the game's CLIB archive appended and a trailer at the very
// end; standalone .ags files are the archive alone. Both are what ScummVM
// and the AGS runtime load, so the exe is emitted as a payload too.
//
// Details: "dataVersion" (the game file format number after the
// "Adventure Creator Game File v2" signature, when found). With a version
// 30 archive (AGS 3.5+) the game data entry is located through the
// directory; older archives are scanned near the archive start.
type agsDetector struct{}

const (
	agsHeadSig = "CLIB\x1a"
	agsTailSig = "CLIB\x1a\x02\x03"
	agsDataSig = "Adventure Creator Game File v2"
)

func (agsDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".ags") {
		r, err := s.open(index)
		if err != nil {
			continue
		}
		info := agsInfo(r)
		if info == nil {
			continue
		}
		s.addFileCandidate(index, FlavorAGS, info)
		// the engine shipped next to a separate data file
		s.annotateNativesIn(parentDir(s.lowerFiles[index]), info)
	}

	for _, c := range append([]*Candidate(nil), s.candidates...) {
		if c.Flavor != FlavorNativeWindows {
			continue
		}
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		tail := s.readTail(index, len(agsTailSig))
		if string(tail) != agsTailSig {
			continue
		}
		r, err := s.open(index)
		if err != nil {
			continue
		}
		info := agsInfo(r)
		if info == nil {
			continue
		}
		c.setEngine(cloneEngine(info))
		p := s.addFileCandidate(index, FlavorAGS, info)
		p.Mode = c.Mode
	}
	return nil
}

// agsInfo checks for the CLIB head at offset 0 or the tail record at the
// end, then looks for the game file signature at the archive start to
// read the data version.
func agsInfo(r *probeReader) *EngineInfo {
	var start int64 = -1
	if string(r.readHead(len(agsHeadSig))) == agsHeadSig {
		start = 0
	} else {
		tail := r.readTail(4 + len(agsTailSig))
		if tail == nil || string(tail[4:]) != agsTailSig {
			return nil
		}
		start = int64(binary.LittleEndian.Uint32(tail[0:4]))
		if start >= r.size || string(r.readAt(start, len(agsHeadSig))) != agsHeadSig {
			return nil
		}
	}

	info := &EngineInfo{Engine: EngineAGS}
	window := r.readAt(start, min(64<<10, int(r.size-start)))
	if off, ok := agsDataOffset(window); ok {
		if hdr := r.readAt(start+off, len(agsDataSig)+4); hdr != nil && string(hdr[:len(agsDataSig)]) == agsDataSig {
			info.detail("dataVersion", int(binary.LittleEndian.Uint32(hdr[len(agsDataSig):])))
			return info
		}
	}
	if i := bytes.Index(window, []byte(agsDataSig)); i >= 0 && i+len(agsDataSig)+4 <= len(window) {
		info.detail("dataVersion", int(binary.LittleEndian.Uint32(window[i+len(agsDataSig):])))
	}
	return info
}

// agsDataOffset walks a version 30 CLIB directory for the .dta entry:
// after the head signature come u8 version, u8 index, u32 library count
// and the NUL-terminated library names, then u32 file count and per file
// a NUL-terminated name, u8 library index, i64 offset, i64 size.
func agsDataOffset(dir []byte) (int64, bool) {
	pos := len(agsHeadSig)
	if len(dir) < pos+6 || dir[pos] != 30 {
		return 0, false
	}
	pos += 2
	readString := func() (string, bool) {
		end := bytes.IndexByte(dir[pos:], 0)
		if end < 0 {
			return "", false
		}
		str := string(dir[pos : pos+end])
		pos += end + 1
		return str, true
	}
	readU32 := func() (uint32, bool) {
		if pos+4 > len(dir) {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(dir[pos:])
		pos += 4
		return v, true
	}

	libs, ok := readU32()
	if !ok || libs > 64 {
		return 0, false
	}
	for i := uint32(0); i < libs; i++ {
		if _, ok := readString(); !ok {
			return 0, false
		}
	}
	files, ok := readU32()
	if !ok || files > 100000 {
		return 0, false
	}
	for i := uint32(0); i < files; i++ {
		name, ok := readString()
		if !ok || pos+17 > len(dir) {
			return 0, false
		}
		lib := dir[pos]
		offset := int64(binary.LittleEndian.Uint64(dir[pos+1:]))
		pos += 17
		if lib == 0 && strings.HasSuffix(strings.ToLower(name), ".dta") {
			return offset, offset > 0
		}
	}
	return 0, false
}
