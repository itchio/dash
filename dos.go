package dash

import (
	"encoding/binary"
	"sort"
	"strings"
)

// dosDetector emits one directory candidate per folder holding 16-bit
// executables: MZ files whose e_lfanew is absent, out of range, or points
// at an NE/LE/LX header instead of PE, and .com files, which have no header
// at all and are trusted on size alone.
//
// Details: "executables" (names of the DOS exes found in the folder),
// "confidence" ("ext" when only .com files were found).
type dosDetector struct{}

func (dosDetector) detect(s *scan) error {
	byDir := make(map[string][]string)
	confirmed := make(map[string]bool)
	for index, lower := range s.lowerFiles {
		f := s.container.Files[index]
		dir := parentDir(lower)
		switch {
		case strings.HasSuffix(lower, ".exe"):
			if c := s.candidateAt(lower); c != nil && c.Flavor == FlavorNativeWindows {
				continue
			}
			if !isDOSExecutable(s.readHead(index, 0x40), f.Size) {
				continue
			}
			confirmed[dir] = true
		case strings.HasSuffix(lower, ".com"):
			// a .com image is loaded whole into one 64 KiB segment
			if f.Size == 0 || f.Size > 0xff00 {
				continue
			}
		default:
			continue
		}
		byDir[dir] = append(byDir[dir], lowerBase(f.Path))
	}

	dirs := make([]string, 0, len(byDir))
	for dir := range byDir {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		names := byDir[dir]
		sort.Strings(names)
		info := &EngineInfo{Engine: EngineDOS}
		info.detail("executables", names)
		if !confirmed[dir] {
			info.detail("confidence", "ext")
		}
		s.addDirCandidate(s.originalDir(dir), FlavorDOS, info)
	}
	return nil
}

func isDOSExecutable(head []byte, size int64) bool {
	if len(head) < 0x40 || head[0] != 'M' || head[1] != 'Z' {
		return false
	}
	// e_lfarlc: relocation table offset. 0x40 or more means the header is
	// extended and e_lfanew is meaningful.
	if binary.LittleEndian.Uint16(head[0x18:0x1a]) < 0x40 {
		return true
	}
	off := int64(binary.LittleEndian.Uint32(head[0x3c:0x40]))
	if off == 0 || off+4 > size {
		return true
	}
	return false
}
