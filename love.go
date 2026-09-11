package dash

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strings"
)

var loveVersionPattern = regexp.MustCompile(`t\.version\s*=\s*"([^"]+)"`)

func loveEngine(version string) *EngineInfo {
	return &EngineInfo{Engine: EngineLove, Version: version}
}

func loveCandidate(path string, version string) *Candidate {
	return &Candidate{
		Flavor:   FlavorLove,
		Path:     path,
		LoveInfo: &LoveInfo{Version: version},
		Engine:   loveEngine(version),
	}
}

// sniffLoveConf handles an unpacked LÖVE game: conf.lua marks its folder.
func sniffLoveConf(r io.Reader, dir string) (*Candidate, error) {
	return loveCandidate(dir, loveConfVersion(r)), nil
}

func loveConfVersion(r io.Reader) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		matches := loveVersionPattern.FindSubmatch(s.Bytes())
		if len(matches) == 2 {
			return string(matches[1])
		}
	}
	return ""
}

// sniffLoveArchive handles a .love file, which is a zip with main.lua at
// its root.
func sniffLoveArchive(r *probeReader, path string, size int64) (*Candidate, error) {
	version, _ := loveArchiveVersion(r)
	return loveCandidate(path, version), nil
}

// loveArchiveVersion looks for main.lua and conf.lua in a zip, which may
// be fused to an executable. Returns the version (possibly empty) and
// whether the zip is a LÖVE game at all.
func loveArchiveVersion(r *probeReader) (string, bool) {
	zr := openZip(r)
	if zr == nil {
		return "", false
	}
	if zipEntry(zr, "main.lua", true) == nil {
		return "", false
	}
	conf := zipReadEntry(zipEntry(zr, "conf.lua", true), 64<<10)
	if conf == nil {
		return "", true
	}
	return loveConfVersion(bytes.NewReader(conf)), true
}

// loveDetector finds fused executables: a native binary with a .love zip
// appended. The executable is both the launcher and the payload, so it is
// annotated and a love candidate is emitted for the same path.
type loveDetector struct{}

func (loveDetector) detect(s *scan) error {
	for _, c := range append([]*Candidate(nil), s.candidates...) {
		switch c.Flavor {
		case FlavorNativeWindows, FlavorNativeLinux, FlavorNativeMacos:
		case FlavorAppMacos:
			// LÖVE macOS games ship love.framework in the bundle and the
			// game as Contents/Resources/*.love, which is its own candidate
			lower := strings.ToLower(c.Path)
			if s.hasDir(lower + "/contents/frameworks/love.framework") {
				c.setEngine(loveEngine(""))
			}
			continue
		default:
			continue
		}
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		if !bytes.Contains(s.readTail(index, tailWindow), []byte("PK\x05\x06")) {
			continue
		}
		r, err := s.open(index)
		if err != nil {
			continue
		}
		version, isLove := loveArchiveVersion(r)
		if !isLove {
			continue
		}
		c.setEngine(loveEngine(version))
		lc := loveCandidate(c.Path, version)
		lc.Size = c.Size
		lc.Mode = c.Mode
		lc.Depth = c.Depth
		s.candidates = append(s.candidates, lc)
	}
	return nil
}
