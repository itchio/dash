package dash

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// pythonDetector annotates PyInstaller executables by the archive cookie
// near their end, and executables next to a main.py that imports pygame.
//
// Details: "packager" ("pyinstaller"), "framework" ("pygame"). Version
// is the bundled Python's, from the cookie.
type pythonDetector struct{}

var pyinstallerMagic = []byte("MEI\014\013\012\013\016")
var pygameImportPattern = regexp.MustCompile(`(?m)^\s*(import\s+pygame|from\s+pygame)`)

func (pythonDetector) detect(s *scan) error {
	for _, c := range s.candidates {
		switch c.Flavor {
		case FlavorNativeWindows, FlavorNativeLinux, FlavorNativeMacos:
		default:
			continue
		}
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		tail := s.readTail(index, tailWindow)
		i := bytes.LastIndex(tail, pyinstallerMagic)
		if i < 0 {
			continue
		}
		info := &EngineInfo{Engine: EnginePython}
		info.detail("packager", "pyinstaller")
		// cookie: magic, u32 length, u32 toc offset, u32 toc length, u32 python version
		if i+24 <= len(tail) {
			info.Version = pyinstallerPythonVersion(binary.BigEndian.Uint32(tail[i+20 : i+24]))
		}
		c.setEngine(info)
	}

	for _, index := range s.filesNamed("main.py") {
		if !pygameImportPattern.Match(s.readHead(index, 16<<10)) {
			continue
		}
		info := &EngineInfo{Engine: EnginePython}
		info.detail("framework", "pygame")
		s.annotateNativesIn(parentDir(s.lowerFiles[index]), info)
	}
	return nil
}

// pyinstallerPythonVersion decodes the cookie's version field, which was
// major*10+minor before Python 3.10 and major*100+minor since.
func pyinstallerPythonVersion(v uint32) string {
	switch {
	case v == 0 || v > 9999:
		return ""
	case v < 100:
		return fmt.Sprintf("%d.%d", v/10, v%10)
	default:
		return fmt.Sprintf("%d.%d", v/100, v%100)
	}
}
