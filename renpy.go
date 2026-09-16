package dash

// Reference game pages used to verify this detector:
//   https://doraxnobi.itch.io/milfy-multiverse
//     (NSFW) Ren'Py 8.1.3 pc build, version in vc_version.py
//   https://bluusorbet.itch.io/once-you-said-no
//     macOS bundle, game in Contents/Resources/autorun, 8.3.6

import (
	"regexp"
	"strings"
)

// renpyDetector emits the folder holding game/ as a payload and annotates
// the launchers Ren'Py places next to it and under lib/.
//
// Version comes from renpy/__init__.py, or the Python generation in lib/
// when the engine folder is absent.
type renpyDetector struct{}

// Ren'Py 7 hardcodes version_tuple in renpy/__init__.py; Ren'Py 8 keeps
// the string in renpy/vc_version.py
var renpyVersionPattern = regexp.MustCompile(`version_tuple\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)`)
var renpyVCVersionPattern = regexp.MustCompile(`(?m)^version\s*=\s*['"](\d+\.\d+\.\d+)`)

func (renpyDetector) detect(s *scan) error {
	seen := make(map[string]bool)
	for _, lower := range s.lowerFiles {
		// find every X/game/ that holds Ren'Py script or archives
		i := strings.LastIndex(lower, "/game/")
		var root string
		switch {
		case i >= 0:
			root = lower[:i]
		case strings.HasPrefix(lower, "game/"):
			root = ""
		default:
			continue
		}
		if seen[root] {
			continue
		}
		ext := getExt(lower)
		if ext != ".rpy" && ext != ".rpyc" && ext != ".rpa" && !s.hasDir(joinPath(root, "renpy")) {
			continue
		}
		seen[root] = true

		info := &EngineInfo{Engine: EngineRenpy, Version: renpyVersion(s, root)}
		s.addDirCandidate(s.originalDir(root), FlavorRenpy, info)
		s.annotateAround(root, info)
		for _, c := range s.nativesUnder(joinPath(root, "lib")) {
			c.setEngine(cloneEngine(info))
		}
	}
	return nil
}

func renpyVersion(s *scan, root string) string {
	if index, ok := s.file(joinPath(root, "renpy/vc_version.py")); ok {
		if m := renpyVCVersionPattern.FindSubmatch(s.readHead(index, 4096)); m != nil {
			return string(m[1])
		}
	}
	if index, ok := s.file(joinPath(root, "renpy/__init__.py")); ok {
		if m := renpyVersionPattern.FindSubmatch(s.readHead(index, 64<<10)); m != nil {
			return string(m[1]) + "." + string(m[2]) + "." + string(m[3])
		}
	}
	libPrefix := joinPath(root, "lib") + "/"
	for d := range s.dirs {
		if !strings.HasPrefix(d, libPrefix) {
			continue
		}
		name := strings.TrimPrefix(d, libPrefix)
		if strings.Contains(name, "/") {
			continue
		}
		switch {
		case strings.HasPrefix(name, "py3-"):
			return "8"
		case strings.HasPrefix(name, "py2-"), name == "linux-x86_64", name == "windows-i686", name == "darwin-x86_64":
			return "7"
		}
	}
	return ""
}
