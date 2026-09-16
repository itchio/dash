package dash

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/itchio/headway/state"
	"github.com/itchio/lake"
	"github.com/itchio/lake/pools"
	"github.com/itchio/lake/tlc"
)

func TestLaunchTargetsFolderAndZip(t *testing.T) {
	root := t.TempDir()
	content := []byte("<html>game</html>")
	if err := os.WriteFile(filepath.Join(root, "index.html"), content, 0644); err != nil {
		t.Fatal(err)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256(content))
	folder, err := ScanLaunchTargets(root, ConfigureParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(folder) != 1 || folder[0].Path != "index.html" || folder[0].Sha256 != wantHash || folder[0].Size != int64(len(content)) {
		t.Fatalf("unexpected folder report: %+v", folder)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "game.zip")
	if err := os.WriteFile(archive, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	zipped, err := ScanLaunchTargets(archive, ConfigureParams{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(folder, zipped) {
		t.Fatalf("folder %+v != ZIP %+v", folder, zipped)
	}
}

func TestLaunchTargetsEmptyAndFiltered(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("game"), 0644); err != nil {
		t.Fatal(err)
	}
	targets, err := ScanLaunchTargets(root, ConfigureParams{Filter: func(string) tlc.FilterResult { return tlc.FilterIgnore }})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[]" {
		t.Fatalf("expected [], got %s", data)
	}
}

func TestLaunchTargetJSONContract(t *testing.T) {
	verdict := &Verdict{Candidates: []*Candidate{{
		Path: "Game.app", Depth: 1, Flavor: FlavorAppMacos, Arch: ArchAmd64,
		Helper: "electron", Mode: 0755, Spell: []string{"private diagnostic"},
		Engine:    &EngineInfo{Engine: Engine("test"), Version: "1", Details: map[string]any{"key": "value"}},
		LinuxInfo: &LinuxInfo{}, WindowsInfo: &WindowsInfo{}, MacosInfo: &MacosInfo{},
	}}}
	targets := launchTargetsFromVerdict(verdict, &tlc.Container{}, nil, &state.Consumer{})
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	expected := []string{"path", "depth", "flavor", "arch", "helper", "engine", "linux_info", "windows_info", "macos_info"}
	if len(records) != 1 || len(records[0]) != len(expected) {
		t.Fatalf("unexpected fields: %s", data)
	}
	for _, key := range expected {
		if _, ok := records[0][key]; !ok {
			t.Errorf("missing %s: %s", key, data)
		}
	}
	if !bytes.Contains(records[0]["engine"], []byte(`"key":"value"`)) {
		t.Fatalf("lost engine details: %s", data)
	}
	minimal, err := json.Marshal(LaunchTarget{Path: ".", Depth: 1, Flavor: Flavor("renpy")})
	if err != nil {
		t.Fatal(err)
	}
	if string(minimal) != `{"path":".","depth":1,"flavor":"renpy"}` {
		t.Fatalf("unexpected minimal record: %s", minimal)
	}
}

type reportPool struct {
	lake.Pool
	reader io.ReadSeeker
	closed bool
}

func (p *reportPool) GetReadSeeker(int64) (io.ReadSeeker, error) { return p.reader, nil }
func (p *reportPool) GetSize(int64) int64                        { return 4 }
func (p *reportPool) Close() error                               { p.closed = true; return nil }

type brokenReportReader struct{ io.ReadSeeker }

func (r brokenReportReader) Read([]byte) (int, error) { return 0, fmt.Errorf("read failed") }

func TestLaunchTargetHashRewindsAndWarns(t *testing.T) {
	reader := strings.NewReader("game")
	_, _ = reader.Seek(3, io.SeekStart)
	pool := &reportPool{reader: reader}
	hash := launchTargetHash(pool, 0, "game", &state.Consumer{})
	if hash != fmt.Sprintf("%x", sha256.Sum256([]byte("game"))) {
		t.Fatalf("hash did not read whole file: %s", hash)
	}
	pool.reader = brokenReportReader{strings.NewReader("game")}
	warned := false
	hash = launchTargetHash(pool, 0, "game", &state.Consumer{OnMessage: func(_, _ string) { warned = true }})
	if !warned || hash != "" {
		t.Fatalf("failed hash: warned=%v hash=%s", warned, hash)
	}
}

func TestLaunchTargetsContainerSelectionAndOwnership(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"index.html", "excluded.bat"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("game content"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	container, err := tlc.WalkAny(root, tlc.WalkOpts{Filter: func(name string) tlc.FilterResult {
		if name == "excluded.bat" {
			return tlc.FilterIgnore
		}
		return tlc.FilterKeep
	}})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pools.New(container, root)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tracked := &reportPool{Pool: pool}
	targets, err := ScanLaunchTargetsContainer(container, &ownershipPool{Pool: pool, tracker: tracked}, ConfigureParams{
		Filter: func(string) tlc.FilterResult { t.Fatal("must not re-filter container"); return tlc.FilterIgnore },
	})
	if err != nil {
		t.Fatal(err)
	}
	if tracked.closed {
		t.Fatal("caller pool was closed")
	}
	if len(targets) != 1 || targets[0].Path != "index.html" {
		t.Fatalf("unexpected selection: %+v", targets)
	}
}

type ownershipPool struct {
	lake.Pool
	tracker *reportPool
}

func (p *ownershipPool) Close() error { p.tracker.closed = true; return nil }

func TestLaunchTargetsDeepProbeAndDirectory(t *testing.T) {
	targets, err := ScanLaunchTargets("testdata/linux-sdl", ConfigureParams{})
	if err != nil {
		t.Fatal(err)
	}
	foundImports := false
	for _, target := range targets {
		if target.LinuxInfo != nil && len(target.LinuxInfo.Imports) > 0 {
			foundImports = true
		}
	}
	if !foundImports {
		t.Fatal("launch profile did not enable deep probing")
	}
	targets, err = ScanLaunchTargets("testdata/darwin", ConfigureParams{})
	if err != nil {
		t.Fatal(err)
	}
	foundBundle := false
	for _, target := range targets {
		if target.Flavor == FlavorAppMacos {
			foundBundle = true
			if target.Size != 0 || target.Sha256 != "" {
				t.Fatalf("directory has file metadata: %+v", target)
			}
		}
	}
	if !foundBundle {
		t.Fatal("missing macOS bundle")
	}
}

func TestFilterContainerVerdictDoesNotProbeFilesystem(t *testing.T) {
	consumer := &state.Consumer{OnMessage: func(level, message string) {
		if level == "warning" {
			t.Errorf("unexpected filesystem probe: %s", message)
		}
	}}
	verdict := Verdict{Candidates: []*Candidate{
		{Path: "game.exe", Depth: 1, Flavor: FlavorNativeWindows, Arch: ArchAmd64},
		{Path: "setup.exe", Depth: 1, Flavor: FlavorNativeWindows, Arch: ArchAmd64,
			WindowsInfo: &WindowsInfo{InstallerType: WindowsInstallerTypeInno}},
	}}
	filtered := verdict.Filter(consumer, FilterParams{OS: "windows", Arch: "amd64"})
	if len(filtered.Candidates) != 1 || filtered.Candidates[0].Path != "game.exe" {
		t.Fatalf("unexpected candidates: %+v", filtered.Candidates)
	}
}

func TestLaunchTargetsZeroByteFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	targets, err := ScanLaunchTargets(root, ConfigureParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Size != 0 || targets[0].Sha256 != fmt.Sprintf("%x", sha256.Sum256(nil)) {
		t.Fatalf("unexpected empty file report: %+v", targets)
	}
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"size"`)) {
		t.Fatalf("zero size must retain existing omission behavior: %s", data)
	}
}

type unavailableReportPool struct{ lake.Pool }

func (p unavailableReportPool) GetReadSeeker(int64) (io.ReadSeeker, error) {
	return nil, fmt.Errorf("open failed")
}

func TestLaunchTargetPreservesSizeWhenOpenFails(t *testing.T) {
	container := &tlc.Container{Files: []*tlc.File{{Path: "game.exe", Size: 123}}}
	verdict := &Verdict{Candidates: []*Candidate{{Path: "game.exe", Depth: 1, Flavor: FlavorNativeWindows}}}
	warned := false
	targets := launchTargetsFromVerdict(verdict, container, unavailableReportPool{}, &state.Consumer{
		OnMessage: func(_, _ string) { warned = true },
	})
	if !warned || len(targets) != 1 || targets[0].Size != 123 || targets[0].Sha256 != "" {
		t.Fatalf("size lost on open failure: warned=%v targets=%+v", warned, targets)
	}
}
