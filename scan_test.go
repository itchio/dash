package dash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itchio/lake/pools"
	"github.com/itchio/lake/tlc"
)

func TestScanDirectoryIndexes(t *testing.T) {
	container := &tlc.Container{
		Files: []*tlc.File{
			{Path: "Game/Data/level.dat"},
			{Path: "Game/run.sh"},
			{Path: "Game/Data/Sub/x.js"},
			{Path: "Other/a.js"},
		},
		Dirs: []*tlc.Dir{{Path: "Game"}, {Path: "Empty/Nested"}},
	}
	s := newScan(ConfigureParams{}, nil, container)

	if got := s.originalDir("game/data"); got != "Game/Data" {
		t.Fatalf("originalDir = %q", got)
	}
	if got := s.originalDir("empty/nested"); got != "Empty/Nested" {
		t.Fatalf("originalDir from dir entry = %q", got)
	}
	if got := s.originalDir("missing"); got != "missing" {
		t.Fatalf("originalDir fallback = %q", got)
	}
	if got := s.filesInDir["game/data"]; len(got) != 1 || got[0] != 0 {
		t.Fatalf("filesInDir = %v", got)
	}
	if got := s.filesInDir["game"]; len(got) != 1 || got[0] != 1 {
		t.Fatalf("filesInDir root of game = %v", got)
	}
}

func TestScanCandidateIndexFollowsAppends(t *testing.T) {
	container := &tlc.Container{Files: []*tlc.File{
		{Path: "App.app/Contents/MacOS/Game"},
		{Path: "App.app/Contents/MacOS/Helper"},
		{Path: "lib/x86_64/game"},
	}}
	s := newScan(ConfigureParams{}, nil, container)

	first := s.addFileCandidate(0, FlavorNativeMacos, nil)
	if s.candidateAt("app.app/contents/macos/game") != first {
		t.Fatal("candidateAt should find the first candidate")
	}
	if got := s.nativesIn("app.app/contents/macos"); len(got) != 1 {
		t.Fatalf("nativesIn = %d", len(got))
	}

	s.addFileCandidate(1, FlavorNativeMacos, nil)
	s.addFileCandidate(2, FlavorNativeLinux, nil)
	s.addDirCandidate("App.app", FlavorAppMacos, nil)
	if got := s.nativesIn("app.app/contents/macos"); len(got) != 2 || got[0] != first {
		t.Fatalf("nativesIn after append = %d", len(got))
	}
	if got := s.nativesUnder("app.app"); len(got) != 2 {
		t.Fatalf("nativesUnder = %d", len(got))
	}
	if got := s.nativesUnder(""); len(got) != 4 {
		t.Fatalf("nativesUnder root = %d", len(got))
	}
	if c := s.candidateAt("app.app"); c == nil || c.Flavor != FlavorAppMacos {
		t.Fatalf("dir candidate = %+v", c)
	}
}

func TestReadBundleExecutableSizeCap(t *testing.T) {
	root := t.TempDir()
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleExecutable</key><string>Game</string></dict></plist>`
	big := "<plist>" + strings.Repeat("<array>", maxBundlePlistSize/7) + "</plist>"
	for name, content := range map[string]string{"ok.plist": plist, "big.plist": big} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	container, err := tlc.WalkDir(root, tlc.WalkOpts{Filter: tlc.KeepAllFilter})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pools.New(container, root)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for i, f := range container.Files {
		exe, err := readBundleExecutable(pool, int64(i))
		switch f.Path {
		case "ok.plist":
			if err != nil || exe != "Game" {
				t.Fatalf("ok.plist: exe=%q err=%v", exe, err)
			}
		case "big.plist":
			if err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("big.plist: expected size error, got exe=%q err=%v", exe, err)
			}
		}
	}
}
