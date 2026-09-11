package dash

import (
	"encoding/json"
	"strings"
)

// shellDetector annotates Electron and NW.js shells and surfaces the web
// game inside them as an html candidate when package.json points at one.
// NW.js apps keep package.json next to the binary, in package.nw (a folder
// or a zip), or in resources/app.nw.
//
// Details: "shell" ("electron" or "nwjs"). Version comes from Electron's
// `version` file when the build still ships one.
type shellDetector struct{}

func (shellDetector) detect(s *scan) error {
	for _, c := range append([]*Candidate(nil), s.candidates...) {
		lower := strings.ToLower(c.Path)
		var dir string
		switch c.Flavor {
		case FlavorNativeWindows, FlavorNativeLinux:
			dir = parentDir(lower)
		case FlavorAppMacos:
			dir = lower + "/contents"
		default:
			continue
		}

		var info *EngineInfo
		var pkgIndex int
		var hasPkg bool
		var pkgData []byte
		var pkgDir string
		switch {
		case s.hasFile(joinPath(dir, "resources/app.asar")), s.hasFile(joinPath(dir, "resources/app/package.json")),
			s.hasDir(dir + "/frameworks/electron framework.framework"):
			info = &EngineInfo{Engine: EngineElectron}
			info.detail("shell", "electron")
			pkgIndex, hasPkg = s.file(joinPath(dir, "resources/app/package.json"))
			if index, ok := s.file(joinPath(parentDir(lower), "version")); ok {
				v := strings.TrimSpace(string(s.readHead(index, 32)))
				info.Version = strings.TrimPrefix(v, "v")
			}
		case s.hasFile(joinPath(dir, "nw.pak")), s.hasFile(joinPath(dir, "nw.dll")), s.hasFile(joinPath(dir, "libnw.so")),
			s.hasFile(joinPath(dir, "nw_100_percent.pak")), s.hasFile(joinPath(dir, "resources/nw.pak")),
			s.hasDir(dir + "/frameworks/nwjs framework.framework"), s.hasDir(dir + "/versions"):
			info = &EngineInfo{Engine: EngineNWJS}
			info.detail("shell", "nwjs")
			for _, rel := range []string{"package.json", "package.nw/package.json", "resources/app.nw/package.json"} {
				if pkgIndex, hasPkg = s.file(joinPath(dir, rel)); hasPkg {
					break
				}
			}
			if !hasPkg {
				// package.nw as a zip: the html inside is not reachable as a
				// file, but package.json still tells the shell apart
				if nwIndex, ok := s.file(joinPath(dir, "package.nw")); ok {
					if r, err := s.open(nwIndex); err == nil {
						if zr := openZip(r); zr != nil {
							pkgData = zipReadEntry(zipEntry(zr, "package.json", true), 64<<10)
						}
					}
				}
			}
		default:
			continue
		}
		c.setEngine(cloneEngine(info))

		if hasPkg {
			pkgData = s.readHead(pkgIndex, 64<<10)
			pkgDir = parentDir(s.lowerFiles[pkgIndex])
		}
		if pkgData == nil {
			continue
		}
		main := packageMain(pkgData)
		if main == "" || !strings.HasSuffix(strings.ToLower(main), ".html") {
			continue
		}
		if !hasPkg {
			continue
		}
		htmlPath := joinPath(pkgDir, strings.ToLower(strings.TrimPrefix(main, "./")))
		htmlIndex, ok := s.file(htmlPath)
		if !ok {
			continue
		}
		if html := s.candidateAt(htmlPath); html != nil {
			html.setEngine(cloneEngine(info))
			continue
		}
		s.addFileCandidate(htmlIndex, FlavorHTML, cloneEngine(info))
	}
	return nil
}

func packageMain(data []byte) string {
	var pkg struct {
		Main string `json:"main"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ""
	}
	return strings.ReplaceAll(pkg.Main, "\\", "/")
}
