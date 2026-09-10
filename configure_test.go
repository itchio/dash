package dash_test

import (
	"path/filepath"
	"testing"

	"github.com/itchio/dash"
	"github.com/itchio/headway/state"
	"github.com/stretchr/testify/assert"
)

func makeConsumer(t *testing.T) *state.Consumer {
	consumer := &state.Consumer{
		OnMessage: func(lvl string, msg string) {
			t.Helper()
			t.Logf("[%s] %s", lvl, msg)
		},
	}
	return consumer
}

func configureParams(t *testing.T) dash.ConfigureParams {
	return dash.ConfigureParams{
		Consumer: makeConsumer(t),
	}
}

func fixParams(t *testing.T) dash.FixPermissionsParams {
	return dash.FixPermissionsParams{
		Consumer: makeConsumer(t),
		DryRun:   true,
	}
}

func Test_ConfigureWindows(t *testing.T) {
	root := filepath.Join("testdata", "windows")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	assert.EqualValues(t, 4, len(v.Candidates), "finds all candidates on first walk")

	v32 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "386"})

	assert.EqualValues(t, 1, len(v32.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "launcher.bat", v32.Candidates[0].Path, "batch won")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "launcher.bat", v64.Candidates[0].Path, "batch won")
}

func Test_ConfigureWindowsIL2CPP(t *testing.T) {
	root := filepath.Join("testdata", "windows-il2cpp")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	assert.EqualValues(t, 3, len(v.Candidates), "finds all candidates on first walk")

	v32 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "386"})

	assert.EqualValues(t, 1, len(v32.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "game.exe", v32.Candidates[0].Path, "game won")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "game.exe", v64.Candidates[0].Path, "game won")
}

func Test_ConfigureWindowsHtml(t *testing.T) {
	root := filepath.Join("testdata", "windows-html")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	assert.EqualValues(t, 2, len(v.Candidates), "finds all candidates on first walk")

	v32 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "386"})

	assert.EqualValues(t, 1, len(v32.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "game.exe", v32.Candidates[0].Path, "batch won")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "game.exe", v64.Candidates[0].Path, "batch won")
}

func Test_ConfigureWindowsFakeShebang(t *testing.T) {
	// data files that start with "#!" but don't name an interpreter path
	// (e.g. RP6502 ROM images) must not be treated as scripts,
	// see https://github.com/itchio/itch/issues/3468
	root := filepath.Join("testdata", "windows-fake-shebang")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	assert.EqualValues(t, 1, len(v.Candidates), "only the html file is a candidate")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "index.html", v64.Candidates[0].Path, "html won")
}

func Test_ConfigureScriptAndHtml(t *testing.T) {
	root := filepath.Join("testdata", "script-and-html")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	assert.EqualValues(t, 2, len(v.Candidates), "finds all candidates on first walk")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "index.html", v64.Candidates[0].Path, "html won, shebang scripts can't run on windows")

	vlinux := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vlinux.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "launch", vlinux.Candidates[0].Path, "script won on linux")
}

func Test_ConfigureJarAndHtml(t *testing.T) {
	// filtering for windows must not come up empty just because
	// none of the candidates are native windows executables
	root := filepath.Join("testdata", "jar-and-html")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	assert.EqualValues(t, 2, len(v.Candidates), "finds all candidates on first walk")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "game.jar", v64.Candidates[0].Path, "jar won")
}

func Test_ConfigureDarwin(t *testing.T) {
	root := filepath.Join("testdata", "darwin")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 4, len(v.Candidates), "finds all candidates on first walk")

	fixed, err := dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")
	assert.EqualValues(t, 3, len(fixed), "had to fix some files")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "Some Grand Game.app", vcopy.Candidates[0].Path, "app wins")
}

func Test_ConfigureDarwinNested(t *testing.T) {
	root := filepath.Join("testdata", "darwin-nested")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 4, len(v.Candidates), "finds all candidates on first walk")

	_, err = dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "osx64/dragonjousting.app", vcopy.Candidates[0].Path, "app wins")
}

func Test_ConfigureDarwinGhost(t *testing.T) {
	root := filepath.Join("testdata", "darwin-ghost")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 3, len(v.Candidates), "finds both execs and one valid app bundle")

	_, err = dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "Awesome Stuff.app", vcopy.Candidates[0].Path, "valid app bundle wins")
}

func Test_ConfigureDarwinSymlink(t *testing.T) {
	root := filepath.Join("testdata", "darwin-symlink")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 1, len(v.Candidates), "finds all candidates on first walk")

	_, err = dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "hello.app", vcopy.Candidates[0].Path, "app wins")
}

func Test_ConfigureLinux(t *testing.T) {
	root := filepath.Join("testdata", "linux")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 5, len(v.Candidates), "finds all candidates on first walk")

	fixed, err := dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")
	assert.EqualValues(t, 5, len(fixed), "fixed some files")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "OpenHexagon", vcopy.Candidates[0].Path, "launcher script wins")
}

func Test_ConfigureLinuxLibs(t *testing.T) {
	root := filepath.Join("testdata", "linux-libs")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 1, len(v.Candidates), "finds all candidates on first walk")

	fixed, err := dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")
	assert.EqualValues(t, 1, len(fixed), "fixed some files")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "game", vcopy.Candidates[0].Path, "binary wins")
}

func Test_ConfigureLinuxDualArch(t *testing.T) {
	root := filepath.Join("testdata", "linux-dual-arch")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 2, len(v.Candidates), "finds all candidates on first walk")

	fixed, err := dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")
	assert.EqualValues(t, 2, len(fixed), "fixed some files")

	v32 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "386"})

	assert.EqualValues(t, 1, len(v32.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "Game.x86", v32.Candidates[0].Path, "launcher script wins")

	v64 := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})

	assert.EqualValues(t, 1, len(v64.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "Game.x86_64", v64.Candidates[0].Path, "launcher script wins")
}

func Test_ConfigureHtmlMany(t *testing.T) {
	root := filepath.Join("testdata", "html", "many")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 1, len(v.Candidates), "finds all candidates on first walk")

	_, err = dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "index.html", vcopy.Candidates[0].Path, "lowest won")
}

func Test_ConfigureHtmlNested(t *testing.T) {
	root := filepath.Join("testdata", "html", "nested")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 1, len(v.Candidates), "finds all candidates on first walk")

	_, err = dash.FixPermissions(v, fixParams(t))
	assert.NoError(t, err, "fixes permissions without problems")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})

	assert.EqualValues(t, 1, len(vcopy.Candidates), "only one candidate left after filtering")
	assert.EqualValues(t, "ThisContainsStuff/index.html", vcopy.Candidates[0].Path, "lowest won")
}

func Test_ConfigureBiggerIsBetter(t *testing.T) {
	root := filepath.Join("testdata", "bigger-is-better")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 3, len(v.Candidates), "finds all candidates on first walk")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})

	assert.EqualValues(t, 3, len(vcopy.Candidates), "three candidates left after filtering")
	assert.EqualValues(t, "tiled.exe", vcopy.Candidates[0].Path, "biggest wins")
}

func Test_ConfigureBlacklist(t *testing.T) {
	root := filepath.Join("testdata", "linux-nodewebkit")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")
	assert.EqualValues(t, 3, len(v.Candidates), "finds all candidates on first walk")

	vcopy := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})

	assert.EqualValues(t, 3, len(vcopy.Candidates), "three candidates left after filtering")
	assert.EqualValues(t, "nw", vcopy.Candidates[0].Path, "non-nacl helper wins")
}

func Test_ConfigureDarwinArch(t *testing.T) {
	root := filepath.Join("testdata", "darwin-arch")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	byPath := make(map[string]*dash.Candidate)
	for _, c := range v.Candidates {
		byPath[c.Path] = c
	}
	assert.EqualValues(t, 15, len(byPath), "finds six bundles, eight bundled execs and one naked exec")

	expected := map[string]struct {
		arch  dash.Arch
		archs []dash.Arch
	}{
		"Silicon.app":                            {dash.ArchArm64, []dash.Arch{dash.ArchArm64}},
		"Silicon.app/Contents/MacOS/silicon":     {dash.ArchArm64, []dash.Arch{dash.ArchArm64}},
		"Intel.app":                              {dash.ArchAmd64, []dash.Arch{dash.ArchAmd64}},
		"Intel.app/Contents/MacOS/intel":         {dash.ArchAmd64, []dash.Arch{dash.ArchAmd64}},
		"Universal.app":                          {dash.ArchUniversal, []dash.Arch{dash.ArchAmd64, dash.ArchArm64}},
		"Universal.app/Contents/MacOS/universal": {dash.ArchUniversal, []dash.Arch{dash.ArchAmd64, dash.ArchArm64}},
		"naked-arm64":                            {dash.ArchArm64, []dash.Arch{dash.ArchArm64}},
		"Legacy.app":                             {dash.ArchUniversal, []dash.Arch{dash.Arch386, dash.ArchAmd64}},
		// helper sorts before the main executable, CFBundleExecutable must win
		"Mixed.app":                                 {dash.ArchArm64, []dash.Arch{dash.ArchArm64}},
		"Mixed.app/Contents/MacOS/aaa-helper":       {dash.ArchAmd64, []dash.Arch{dash.ArchAmd64}},
		"MixedBinary.app":                           {dash.ArchArm64, []dash.Arch{dash.ArchArm64}},
		"MixedBinary.app/Contents/MacOS/aaa-helper": {dash.ArchAmd64, []dash.Arch{dash.ArchAmd64}},
	}
	for path, e := range expected {
		c := byPath[path]
		if !assert.NotNil(t, c, "found %s", path) {
			continue
		}
		assert.EqualValues(t, e.arch, c.Arch, "arch of %s", path)
		if assert.NotNil(t, c.MacosInfo, "macos info of %s", path) {
			assert.EqualValues(t, e.archs, c.MacosInfo.Architectures, "architectures of %s", path)
		}
	}

	paths := func(v dash.Verdict) []string {
		var res []string
		for _, c := range v.Candidates {
			res = append(res, c.Path)
		}
		return res
	}

	arm := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "arm64"})
	assert.ElementsMatch(t, []string{"Silicon.app", "Universal.app", "Mixed.app", "MixedBinary.app"}, paths(arm), "apple silicon prefers native builds over intel-only")

	intel := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})
	assert.ElementsMatch(t, []string{"Intel.app", "Universal.app", "Legacy.app"}, paths(intel), "intel excludes arm64-only builds")
}

func Test_ConfigureDarwinArchNested(t *testing.T) {
	root := filepath.Join("testdata", "darwin-arch-nested")

	v, err := dash.Configure(root, configureParams(t))
	assert.NoError(t, err, "walks without problems")

	paths := func(v dash.Verdict) []string {
		var res []string
		for _, c := range v.Candidates {
			res = append(res, c.Path)
		}
		return res
	}

	arm := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "arm64"})
	assert.ElementsMatch(t, []string{"Silicon.app"}, paths(arm), "top-level native bundle wins on apple silicon")

	// the excluded top-level arm64 bundle must not drag the depth cutoff
	// below the remaining intel bundles
	intel := v.Filter(makeConsumer(t), dash.FilterParams{OS: "darwin", Arch: "amd64"})
	assert.ElementsMatch(t, []string{"intel/Intel.app", "intel/Other.app"}, paths(intel), "deeper intel bundles survive on intel")
}
