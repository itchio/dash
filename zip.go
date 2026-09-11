package dash

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"

	"github.com/itchio/arkive/zip"
)

func sniffZip(r *probeReader, size int64) (*Candidate, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		// not a zip, probably
		return nil, nil
	}

	var engine *EngineInfo
	for _, f := range zr.File {
		path := zipEntryPath(f.Name)
		switch {
		case strings.HasPrefix(path, "com/badlogic/gdx/"):
			engine = &EngineInfo{Engine: EngineLibGDX}
		case strings.HasPrefix(path, "org/lwjgl/") && engine == nil:
			engine = &EngineInfo{Engine: EngineLWJGL}
		}
	}

	for _, f := range zr.File {
		path := zipEntryPath(f.Name)
		if path == "META-INF/MANIFEST.MF" {
			rc, err := f.Open()
			if err != nil {
				// :(
				return nil, nil
			}
			defer rc.Close()

			s := bufio.NewScanner(rc)

			for s.Scan() {
				tokens := strings.SplitN(s.Text(), ":", 2)
				if len(tokens) > 0 && tokens[0] == "Main-Class" {
					mainClass := strings.TrimSpace(tokens[1])
					res := &Candidate{
						Flavor: FlavorJar,
						JarInfo: &JarInfo{
							MainClass: mainClass,
						},
						Engine: engine,
					}
					return res, nil
				}
			}

			// we found the manifest, even if we couldn't read it
			// or it didn't have a main class
			break
		}
	}

	return nil, nil
}

func zipEntryPath(name string) string {
	return filepath.ToSlash(filepath.Clean(filepath.ToSlash(name)))
}

// openZip opens a zip archive that may have data prepended to it (a fused
// executable). Returns nil when the file is not a zip.
func openZip(r *probeReader) *zip.Reader {
	zr, err := zip.NewReader(r, r.size)
	if err != nil {
		return nil
	}
	return zr
}

// zipEntry finds an entry by exact path, or by base name anywhere when
// atRoot is false.
func zipEntry(zr *zip.Reader, name string, atRoot bool) *zip.File {
	lower := strings.ToLower(name)
	for _, f := range zr.File {
		path := strings.ToLower(zipEntryPath(f.Name))
		if path == lower {
			return f
		}
		if !atRoot && strings.HasSuffix(path, "/"+lower) {
			return f
		}
	}
	return nil
}

// zipReadEntry returns up to max bytes of an entry's contents.
func zipReadEntry(f *zip.File, max int64) []byte {
	if f == nil {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	buf, err := io.ReadAll(io.LimitReader(rc, max))
	if err != nil {
		return nil
	}
	return buf
}
