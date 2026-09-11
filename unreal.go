package dash

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// unrealDetector annotates Unreal Engine builds: a root with Engine/ and
// <Project>/Content/Paks/*.pak, launchers at the root and under
// <Project>/Binaries/.
//
// Details: "paks" (count), "pakVersion" (from the first pak's footer).
// Version is the major ("4") when the pak format pins it down, else empty.
type unrealDetector struct{}

var unrealPakMagic = []byte{0xe1, 0x12, 0x6f, 0x5a}

func (unrealDetector) detect(s *scan) error {
	seen := make(map[string]bool)
	for index, lower := range s.lowerFiles {
		if !strings.HasSuffix(lower, ".pak") {
			continue
		}
		paksDir := parentDir(lower)
		if !strings.HasSuffix(paksDir, "/content/paks") {
			continue
		}
		project := parentDir(parentDir(paksDir))
		root := parentDir(project)
		if seen[root] || !s.hasDir(joinPath(root, "engine")) {
			continue
		}
		seen[root] = true

		info := &EngineInfo{Engine: EngineUnreal}
		info.detail("paks", len(s.filesUnder(paksDir)))
		if v, ok := unrealPakVersion(s.readTail(index, 256)); ok {
			info.detail("pakVersion", v)
			if v <= 10 {
				info.Version = "4"
			}
		}

		s.annotateNativesIn(root, info)
		for _, c := range s.nativesUnder(joinPath(project, "binaries")) {
			c.setEngine(cloneEngine(info))
		}
	}
	return nil
}

// unrealPakVersion finds the footer magic, whose position depends on the
// pak version, and returns the version stored right after it.
func unrealPakVersion(tail []byte) (int, bool) {
	i := bytes.LastIndex(tail, unrealPakMagic)
	if i < 0 || i+8 > len(tail) {
		return 0, false
	}
	return int(binary.LittleEndian.Uint32(tail[i+4 : i+8])), true
}
