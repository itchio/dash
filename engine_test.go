package dash_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/itchio/dash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type candidateMap map[string]*dash.Candidate

// configureEngine walks a fixture under testdata/engines and indexes the
// candidates by path, appending the flavor when a path has several.
func configureEngine(t *testing.T, name string, params ...dash.ConfigureParams) (*dash.Verdict, candidateMap) {
	t.Helper()
	p := configureParams(t)
	if len(params) > 0 {
		p = params[0]
		p.Consumer = makeConsumer(t)
	}
	v, err := dash.Configure(filepath.Join("testdata", "engines", name), p)
	require.NoError(t, err)

	byPath := make(candidateMap)
	for _, c := range v.Candidates {
		if _, dup := byPath[c.Path]; dup {
			byPath[c.Path+"#"+string(c.Flavor)] = c
			continue
		}
		byPath[c.Path] = c
	}
	return v, byPath
}

func (m candidateMap) get(t *testing.T, path string) *dash.Candidate {
	t.Helper()
	c := m[path]
	require.NotNil(t, c, "candidate %s", path)
	return c
}

func (m candidateMap) expect(t *testing.T, path string, flavor dash.Flavor, engine dash.Engine, version string) *dash.Candidate {
	t.Helper()
	c := m.get(t, path)
	assert.EqualValues(t, flavor, c.Flavor, "flavor of %s", path)
	if engine == "" {
		assert.Nil(t, c.Engine, "engine of %s", path)
		return c
	}
	if assert.NotNil(t, c.Engine, "engine of %s", path) {
		assert.EqualValues(t, engine, c.Engine.Engine, "engine of %s", path)
		assert.EqualValues(t, version, c.Engine.Version, "engine version of %s", path)
	}
	return c
}

func detail(c *dash.Candidate, key string) any {
	if c == nil || c.Engine == nil || c.Engine.Details == nil {
		return nil
	}
	return c.Engine.Details[key]
}

func candidatePaths(v dash.Verdict) []string {
	var res []string
	for _, c := range v.Candidates {
		res = append(res, c.Path)
	}
	return res
}

func Test_DeepProbe(t *testing.T) {
	// the fixtures are header-only ELFs, so the probe must fail gracefully
	v, err := dash.Configure(filepath.Join("testdata", "linux-arch"), dash.ConfigureParams{Consumer: makeConsumer(t), DeepProbe: true})
	require.NoError(t, err)
	for _, c := range v.Candidates {
		if c.Path == "game.aarch64" {
			assert.EqualValues(t, dash.ArchArm64, c.LinuxInfo.Arch)
			assert.Empty(t, c.LinuxInfo.Imports)
		}
	}

	// the PE stub has no sections either
	_, m := configureEngine(t, "unity", dash.ConfigureParams{DeepProbe: true})
	assert.EqualValues(t, dash.Arch386, m.get(t, "Game.exe").WindowsInfo.Arch)

	if runtime.GOOS != "linux" {
		return
	}
	// a real dynamically linked executable from the host
	root := t.TempDir()
	sh, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "sh"), sh, 0755))

	v, err = dash.Configure(root, dash.ConfigureParams{Consumer: makeConsumer(t), DeepProbe: true})
	require.NoError(t, err)
	require.Len(t, v.Candidates, 1)
	info := v.Candidates[0].LinuxInfo
	require.NotNil(t, info)
	assert.False(t, info.Static)
	assert.NotEmpty(t, info.Imports)
	t.Logf("imports=%v glibc=%s", info.Imports, info.GlibcVersion)

	// without the flag, the record stays at the header
	v, err = dash.Configure(root, dash.ConfigureParams{Consumer: makeConsumer(t)})
	require.NoError(t, err)
	assert.Empty(t, v.Candidates[0].LinuxInfo.Imports)

	// the single-file probe gives the same record
	f, err := os.Open(filepath.Join(root, "sh"))
	require.NoError(t, err)
	defer f.Close()
	single, err := dash.ProbeELF(f)
	require.NoError(t, err)
	assert.EqualValues(t, info, single)
}

func Test_Godot(t *testing.T) {
	_, m := configureEngine(t, "godot")

	m.expect(t, "game.pck", dash.FlavorGodotPck, dash.EngineGodot, "4.2.1")
	assert.EqualValues(t, 2, detail(m["game.pck"], "packFormat"))
	m.expect(t, "game.x86_64", dash.FlavorNativeLinux, dash.EngineGodot, "4.2.1")

	m.expect(t, "embedded/Game.exe", dash.FlavorNativeWindows, dash.EngineGodot, "3.5.2")
	embedded := m.expect(t, "embedded/Game.exe#godot-pck", dash.FlavorGodotPck, dash.EngineGodot, "3.5.2")
	assert.EqualValues(t, true, detail(embedded, "embedded"))
	assert.EqualValues(t, 1, detail(embedded, "packFormat"))

	m.expect(t, "Mac.app", dash.FlavorAppMacos, dash.EngineGodot, "4.2.1")
	m.expect(t, "Mac.app/Contents/Resources/game.pck", dash.FlavorGodotPck, dash.EngineGodot, "4.2.1")
	m.expect(t, "bigembedded/game.x86_64", dash.FlavorNativeLinux, dash.EngineGodot, "4.3.0")
}

func Test_GodotFilter(t *testing.T) {
	v, _ := configureEngine(t, "godot")

	// desktop: unchanged, the native wins and the pck is invisible
	linux := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})
	assert.EqualValues(t, []string{"game.x86_64"}, candidatePaths(linux), "top-level native wins on depth")

	// handheld with a Godot runtime: every pck survives next to the native
	frt := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "arm64", Runtimes: []dash.Flavor{dash.FlavorGodotPck}})
	// the deeper native loses on depth as usual; its embedded pck is a
	// runtime candidate and stays
	assert.ElementsMatch(t, []string{"game.x86_64", "game.pck", "embedded/Game.exe", "Mac.app/Contents/Resources/game.pck", "bigembedded/game.x86_64"}, candidatePaths(frt))
	for _, c := range frt.Candidates {
		if c.Path != "game.x86_64" {
			assert.EqualValues(t, dash.FlavorGodotPck, c.Flavor)
		}
	}

	// runtime for something else: no change
	other := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64", Runtimes: []dash.Flavor{dash.FlavorPico8Cart}})
	assert.EqualValues(t, []string{"game.x86_64"}, candidatePaths(other))
}

func Test_GameMaker(t *testing.T) {
	_, m := configureEngine(t, "gamemaker")

	data := m.expect(t, "data.win", dash.FlavorGameMakerData, dash.EngineGameMaker, "2022.9.1.51")
	assert.EqualValues(t, 17, detail(data, "bytecode"))
	m.expect(t, "Game.exe", dash.FlavorNativeWindows, dash.EngineGameMaker, "2022.9.1.51")

	// GameMaker Studio 2+ leaves the version fields at 2.0.0.0
	m.expect(t, "linux/assets/game.unx", dash.FlavorGameMakerData, dash.EngineGameMaker, "2")
	m.expect(t, "linux/runner", dash.FlavorNativeLinux, dash.EngineGameMaker, "2")
	m.expect(t, "gms1/Game.exe", dash.FlavorNativeWindows, dash.EngineGameMaker, "1.4.1763.0")

	m.expect(t, "Mac.app", dash.FlavorAppMacos, dash.EngineGameMaker, "2")
	m.expect(t, "Mac.app/Contents/MacOS/silicon", dash.FlavorNativeMacos, dash.EngineGameMaker, "2")

	assert.Nil(t, m["notgm/data.win"], "a data.win without FORM/GEN8 is not a payload")
}

func Test_Pico8(t *testing.T) {
	_, m := configureEngine(t, "pico8")
	m.expect(t, "cart.p8", dash.FlavorPico8Cart, dash.EnginePico8, "42")
	png := m.expect(t, "other.p8.png", dash.FlavorPico8Cart, dash.EnginePico8, "")
	assert.EqualValues(t, "ext", detail(png, "confidence"))
	assert.Nil(t, m["notes.p8"])

	p64png := m.expect(t, "town.p64.png", dash.FlavorPicotronCart, dash.EnginePicotron, "")
	assert.EqualValues(t, "ext", detail(p64png, "confidence"))
	p64 := m.expect(t, "town.p64", dash.FlavorPicotronCart, dash.EnginePicotron, "")
	assert.EqualValues(t, "p64", detail(p64, "format"))
	assert.Nil(t, m["notes.p64"])

	// a web export: the cart lives in the .js, the html stays plain
	js := m.expect(t, "web/game.js", dash.FlavorPico8Cart, dash.EnginePico8, "0.2.6")
	assert.EqualValues(t, "js", detail(js, "format"))
	assert.EqualValues(t, 2, detail(js, "carts"))
	m.expect(t, "web/index.html", dash.FlavorHTML, "", "")
	assert.Nil(t, m["web/lib.js"])
}

func Test_ROM(t *testing.T) {
	_, m := configureEngine(t, "rom")

	expected := map[string]struct {
		system    string
		confirmed bool
	}{
		"a.nes":  {"nes", true},
		"b.sfc":  {"snes", true},
		"b2.smc": {"snes", true},
		"c.gb":   {"gb", true},
		"d.gbc":  {"gbc", true},
		"e.gba":  {"gba", true},
		"f.nds":  {"nds", true},
		"g.md":   {"md", true},
		"h.32x":  {"32x", true},
		"i.sms":  {"sms", false},
		"j.pce":  {"pce", false},
		"k.z64":  {"n64", true},
		"l.a26":  {"a26", false},
		"m.d64":  {"c64", false},
		"n.t64":  {"c64", true},
		"o.adf":  {"amiga", true},
		"p.lnx":  {"lynx", true},
		"q.ngp":  {"ngp", true},
		"r.iso":  {"psp", true},
		"s.cue":  {"psx", true},
		"t.chd":  {"", false},
		"u.bin":  {"md", true},
	}
	for path, e := range expected {
		c := m.expect(t, path, dash.FlavorROM, dash.EngineROM, "")
		assert.EqualValues(t, e.system, detail(c, "system"), "system of %s", path)
		if e.confirmed {
			assert.Nil(t, detail(c, "confidence"), "confidence of %s", path)
		} else {
			assert.EqualValues(t, "ext", detail(c, "confidence"), "confidence of %s", path)
		}
	}
	assert.Nil(t, m["fake.nes"], "a .nes without the header is not a ROM")
	assert.Nil(t, m["s.bin"], "the cue's bin is not its own candidate")
	assert.Nil(t, m["readme.md"], "markdown is not a Mega Drive ROM")
	assert.Nil(t, m["junk.bin"], "a .bin without a Sega header is nothing")
	assert.Nil(t, m["big.a26"], "too big for an Atari cartridge")
	assert.Len(t, m, len(expected))
}

func Test_ROMFilter(t *testing.T) {
	v, _ := configureEngine(t, "rom")

	desktop := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})
	assert.Len(t, desktop.Candidates, 22, "with nothing else, every ROM stays")

	snes := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "arm64", Runtimes: []dash.Flavor{"rom:snes"}})
	assert.ElementsMatch(t, []string{"b.sfc", "b2.smc"}, candidatePaths(snes))

	// listing "rom" without a system means every system
	all := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "arm64", Runtimes: []dash.Flavor{dash.FlavorROM}})
	assert.Len(t, all.Candidates, 22)
}

func Test_DOS(t *testing.T) {
	_, m := configureEngine(t, "dos")
	root := m.expect(t, ".", dash.FlavorDOS, dash.EngineDOS, "")
	assert.EqualValues(t, 1, root.Depth)
	assert.EqualValues(t, []string{"game.exe", "setup.exe"}, detail(root, "executables"))
	sub := m.expect(t, "sub", dash.FlavorDOS, dash.EngineDOS, "")
	assert.EqualValues(t, 2, sub.Depth)
	assert.Nil(t, detail(sub, "confidence"))
	com := m.expect(t, "com", dash.FlavorDOS, dash.EngineDOS, "")
	assert.EqualValues(t, "ext", detail(com, "confidence"), ".com files have no header to check")
	assert.Len(t, m, 3)
}

func Test_WAD(t *testing.T) {
	_, m := configureEngine(t, "wad")
	iwad := m.expect(t, "doom.wad", dash.FlavorDoomWad, dash.EngineDoom, "")
	assert.EqualValues(t, "iwad", detail(iwad, "wadType"))
	pwad := m.expect(t, "mod.wad", dash.FlavorDoomWad, dash.EngineDoom, "")
	assert.EqualValues(t, "pwad", detail(pwad, "wadType"))
	pk3 := m.expect(t, "mod.pk3", dash.FlavorDoomWad, dash.EngineDoom, "")
	assert.EqualValues(t, "pk3", detail(pk3, "format"))
	assert.Nil(t, m["junk.pk3"])
	assert.Nil(t, m["junk.wad"])
}

func Test_Renpy(t *testing.T) {
	v, m := configureEngine(t, "renpy")

	dir := m.expect(t, "MyGame", dash.FlavorRenpy, dash.EngineRenpy, "8.1.3")
	assert.EqualValues(t, 2, dir.Depth, "a folder ranks with the files directly inside it")
	m.expect(t, "MyGame/MyGame.exe", dash.FlavorNativeWindows, dash.EngineRenpy, "8.1.3")
	m.expect(t, "MyGame/MyGame.sh", dash.FlavorScript, dash.EngineRenpy, "8.1.3")
	m.expect(t, "MyGame/lib/py3-linux-x86_64/MyGame", dash.FlavorNativeLinux, dash.EngineRenpy, "8.1.3")

	m.expect(t, "MyGame/lib/py3-linux-x86_64/zsync", dash.FlavorNativeLinux, "", "")

	m.expect(t, "Old", dash.FlavorRenpy, dash.EngineRenpy, "7")
	m.expect(t, "Old/lib/linux-x86_64/Old", dash.FlavorNativeLinux, dash.EngineRenpy, "7")

	// Ren'Py 8 moved the version string to vc_version.py
	m.expect(t, "New", dash.FlavorRenpy, dash.EngineRenpy, "8.3.6")
	m.expect(t, "New/New.sh", dash.FlavorScript, dash.EngineRenpy, "8.3.6")

	// desktop: the launcher wins, the folder never shows
	win := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})
	assert.EqualValues(t, []string{"MyGame/MyGame.exe"}, candidatePaths(win))

	linux := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})
	assert.ElementsMatch(t, []string{"MyGame/MyGame.sh", "New/New.sh"}, candidatePaths(linux))

	// with a Ren'Py runtime, both folders come along
	rt := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "arm64", Runtimes: []dash.Flavor{dash.FlavorRenpy}})
	assert.ElementsMatch(t, []string{"MyGame/MyGame.sh", "New/New.sh", "MyGame", "Old", "New"}, candidatePaths(rt))
}

func Test_PayloadFolderNeverShadowsLauncher(t *testing.T) {
	// the folder is depth 1, the launcher depth 3: without a runtime the
	// folder is a data file and must not win on depth
	v, m := configureEngine(t, "renpy-deep")
	m.expect(t, ".", dash.FlavorRenpy, dash.EngineRenpy, "7")
	linux := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})
	assert.EqualValues(t, []string{"lib/linux-x86_64/Deep"}, candidatePaths(linux))

	rt := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "arm64", Runtimes: []dash.Flavor{dash.FlavorRenpy}})
	assert.ElementsMatch(t, []string{".", "lib/linux-x86_64/Deep"}, candidatePaths(rt))
}

func Test_RPGMaker(t *testing.T) {
	_, m := configureEngine(t, "rpgmaker")

	mv := m.expect(t, "mv/www", dash.FlavorRPGMakerMV, dash.EngineRPGMaker, "1.6.2")
	assert.EqualValues(t, "mv", detail(mv, "variant"))
	m.expect(t, "mv/www/index.html", dash.FlavorHTML, dash.EngineRPGMaker, "1.6.2")
	m.expect(t, "mv/Game.exe", dash.FlavorNativeWindows, dash.EngineRPGMaker, "1.6.2")

	mz := m.expect(t, "mz", dash.FlavorRPGMakerMV, dash.EngineRPGMaker, "1.8.0")
	assert.EqualValues(t, "mz", detail(mz, "variant"))

	// without a runtime the html inside the project is what a desktop runs,
	// the folder must not knock it out through the html rule
	sub, err := dash.Configure(filepath.Join("testdata", "engines", "rpgmaker", "mz"), configureParams(t))
	require.NoError(t, err)
	win := sub.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})
	assert.EqualValues(t, []string{"index.html"}, candidatePaths(win))

	xp := m.expect(t, "xp", dash.FlavorRPGMakerXP, dash.EngineRPGMaker, "1")
	assert.EqualValues(t, "xp", detail(xp, "variant"))
	m.expect(t, "xp/Game.exe", dash.FlavorNativeWindows, dash.EngineRPGMaker, "1")

	ace := m.expect(t, "ace", dash.FlavorRPGMakerXP, dash.EngineRPGMaker, "3")
	assert.EqualValues(t, "vxace", detail(ace, "variant"))

	m.expect(t, "2k", dash.FlavorRPGMaker2k, dash.EngineRPGMaker, "")
	m.expect(t, "2k/RPG_RT.exe", dash.FlavorNativeWindows, dash.EngineRPGMaker, "")

	assert.Nil(t, m["other"], "a Game.ini without RGSS is not RPG Maker")
	m.expect(t, "other/Game.exe", dash.FlavorNativeWindows, "", "")
}

func Test_AGS(t *testing.T) {
	_, m := configureEngine(t, "ags")
	m.expect(t, "game.exe", dash.FlavorNativeWindows, dash.EngineAGS, "")
	exe := m.expect(t, "game.exe#ags", dash.FlavorAGS, dash.EngineAGS, "")
	assert.EqualValues(t, 3060021, detail(exe, "dataVersion"))
	data := m.expect(t, "data.ags", dash.FlavorAGS, dash.EngineAGS, "")
	assert.EqualValues(t, 42, detail(data, "dataVersion"))

	// version 30 archives: the data entry is found through the directory,
	// and the engine next to a separate data file is annotated
	v30 := m.expect(t, "v30/Game.ags", dash.FlavorAGS, dash.EngineAGS, "")
	assert.EqualValues(t, 3060021, detail(v30, "dataVersion"))
	m.expect(t, "v30/Game.exe", dash.FlavorNativeWindows, dash.EngineAGS, "")
	v30exe := m.expect(t, "v30exe/Game.exe#ags", dash.FlavorAGS, dash.EngineAGS, "")
	assert.EqualValues(t, 3050006, detail(v30exe, "dataVersion"))
}

func Test_SWF(t *testing.T) {
	_, m := configureEngine(t, "swf")
	m.expect(t, "movie.swf", dash.FlavorSWF, dash.EngineFlash, "10")
	m.expect(t, "projector.exe", dash.FlavorNativeWindows, dash.EngineFlash, "8")
	proj := m.expect(t, "projector.exe#swf", dash.FlavorSWF, dash.EngineFlash, "8")
	assert.EqualValues(t, true, detail(proj, "projector"))
	assert.Nil(t, m["junk.swf"])
}

func Test_SmallPayloads(t *testing.T) {
	_, m := configureEngine(t, "pyxel")
	m.expect(t, "app.pyxapp", dash.FlavorPyxelApp, dash.EnginePyxel, "")

	_, m = configureEngine(t, "tic80")
	c := m.expect(t, "game.tic", dash.FlavorTIC80Cart, dash.EngineTIC80, "")
	assert.EqualValues(t, "ext", detail(c, "confidence"))

	_, m = configureEngine(t, "openbor")
	c = m.expect(t, "Paks/game.pak", dash.FlavorOpenBORPak, dash.EngineOpenBOR, "")
	assert.Nil(t, detail(c, "confidence"), "a pak in Paks/ is the real thing")
	m.expect(t, "OpenBOR.exe", dash.FlavorNativeWindows, dash.EngineOpenBOR, "")
	c = m.expect(t, "loose/other.pak", dash.FlavorOpenBORPak, dash.EngineOpenBOR, "")
	assert.EqualValues(t, "ext", detail(c, "confidence"))
	assert.Nil(t, m["Paks/junk.pak"])
}

func Test_Solarus(t *testing.T) {
	_, m := configureEngine(t, "solarus")
	m.expect(t, "quest.solarus", dash.FlavorSolarusQuest, dash.EngineSolarus, "1.6")
	m.expect(t, "folder", dash.FlavorSolarusQuest, dash.EngineSolarus, "1.7")
	m.expect(t, "folder/solarus-run.exe", dash.FlavorNativeWindows, dash.EngineSolarus, "1.7")
}

func Test_Unity(t *testing.T) {
	_, m := configureEngine(t, "unity")
	win := m.expect(t, "Game.exe", dash.FlavorNativeWindows, dash.EngineUnity, "2022.3.10f1")
	assert.EqualValues(t, "il2cpp", detail(win, "scripting"))
	m.expect(t, "UnityCrashHandler64.exe", dash.FlavorNativeWindows, "", "")

	linux := m.expect(t, "linux/Game.x86_64", dash.FlavorNativeLinux, dash.EngineUnity, "2019.4.40f1")
	assert.EqualValues(t, "mono", detail(linux, "scripting"))

	m.expect(t, "Mac.app", dash.FlavorAppMacos, dash.EngineUnity, "2022.3.10f1")

	web := m.expect(t, "web/index.html", dash.FlavorHTML, dash.EngineUnity, "")
	assert.EqualValues(t, "webgl", detail(web, "platform"))
}

func Test_Unreal(t *testing.T) {
	_, m := configureEngine(t, "unreal")
	root := m.expect(t, "Proj.exe", dash.FlavorNativeWindows, dash.EngineUnreal, "4")
	assert.EqualValues(t, 1, detail(root, "paks"))
	assert.EqualValues(t, 8, detail(root, "pakVersion"))
	m.expect(t, "Proj/Binaries/Win64/Proj-Win64-Shipping.exe", dash.FlavorNativeWindows, dash.EngineUnreal, "4")
}

func Test_DotNet(t *testing.T) {
	_, m := configureEngine(t, "dotnet")
	fna := m.expect(t, "fna/Game.exe", dash.FlavorNativeWindows, dash.EngineFNA, "")
	assert.EqualValues(t, "framework", detail(fna, "dotnet"))
	mg := m.expect(t, "monogame-core/Game.exe", dash.FlavorNativeWindows, dash.EngineMonoGame, "")
	assert.EqualValues(t, "core", detail(mg, "dotnet"))
	m.expect(t, "xna/Game.exe", dash.FlavorNativeWindows, dash.EngineXNA, "")
}

func Test_Annotations(t *testing.T) {
	_, m := configureEngine(t, "hashlink")
	m.expect(t, "game.exe", dash.FlavorNativeWindows, dash.EngineHashLink, "")

	_, m = configureEngine(t, "defold")
	m.expect(t, "game.x86_64", dash.FlavorNativeLinux, dash.EngineDefold, "")
	web := m.expect(t, "web/index.html", dash.FlavorHTML, dash.EngineDefold, "")
	assert.EqualValues(t, "web", detail(web, "platform"))

	_, m = configureEngine(t, "construct")
	c2 := m.expect(t, "c2/index.html", dash.FlavorHTML, dash.EngineConstruct, "2")
	assert.EqualValues(t, "c2", detail(c2, "variant"))
	m.expect(t, "c3/index.html", dash.FlavorHTML, dash.EngineConstruct, "3")
}

func Test_Shell(t *testing.T) {
	_, m := configureEngine(t, "shell")
	el := m.expect(t, "electron/Game.exe", dash.FlavorNativeWindows, dash.EngineElectron, "12.0.0")
	assert.EqualValues(t, "electron", detail(el, "shell"))

	m.expect(t, "nwjs/Game.exe", dash.FlavorNativeWindows, dash.EngineNWJS, "")
	m.expect(t, "nwjs/www/index.html", dash.FlavorHTML, dash.EngineNWJS, "")

	m.expect(t, "electron-unpacked/game", dash.FlavorNativeLinux, dash.EngineElectron, "")
	m.expect(t, "electron-unpacked/resources/app/game.html", dash.FlavorHTML, dash.EngineElectron, "")

	// current NW.js: nw.dll and a zipped package.nw, no html reachable
	m.expect(t, "nwjs-modern/Game.exe", dash.FlavorNativeWindows, dash.EngineNWJS, "")
	assert.Nil(t, m["nwjs-modern/index.html"])
}

func Test_Python(t *testing.T) {
	_, m := configureEngine(t, "python")
	exe := m.expect(t, "game.exe", dash.FlavorNativeWindows, dash.EnginePython, "3.11")
	assert.EqualValues(t, "pyinstaller", detail(exe, "packager"))
	src := m.expect(t, "src/game", dash.FlavorNativeLinux, dash.EnginePython, "")
	assert.EqualValues(t, "pygame", detail(src, "framework"))
}

func Test_Love(t *testing.T) {
	v, m := configureEngine(t, "love")
	c := m.expect(t, "game.love", dash.FlavorLove, dash.EngineLove, "11.5")
	assert.EqualValues(t, "11.5", c.LoveInfo.Version, "LoveInfo stays populated")

	m.expect(t, "fused/Game.exe", dash.FlavorNativeWindows, dash.EngineLove, "11.4")
	fused := m.expect(t, "fused/Game.exe#love", dash.FlavorLove, dash.EngineLove, "11.4")
	assert.EqualValues(t, true, detail(fused, "embedded"))
	m.expect(t, "notfused/Other.exe", dash.FlavorNativeWindows, "", "")
	assert.Nil(t, m["notfused/Other.exe#love"])

	m.expect(t, "unpacked", dash.FlavorLove, dash.EngineLove, "0.10.2")
	m.expect(t, "Love.app", dash.FlavorAppMacos, dash.EngineLove, "")
	m.expect(t, "Love.app/Contents/Resources/game.love", dash.FlavorLove, dash.EngineLove, "11.5")

	// the top-level love candidates outrank the deeper exes by depth, as before
	win := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})
	assert.ElementsMatch(t, []string{"game.love", "unpacked"}, candidatePaths(win))
}

func Test_LoveFusedFilter(t *testing.T) {
	v, m := configureEngine(t, "love-fused")
	m.expect(t, "Game.exe", dash.FlavorNativeWindows, dash.EngineLove, "11.4")
	m.expect(t, "Game.exe#love", dash.FlavorLove, dash.EngineLove, "11.4")
	m.expect(t, "game.x86_64#love", dash.FlavorLove, dash.EngineLove, "")

	// the love rule must not hand a host the exe to run with a love
	// runtime it does not have: the executable is the launch target
	win := v.Filter(makeConsumer(t), dash.FilterParams{OS: "windows", Arch: "amd64"})
	require.Len(t, win.Candidates, 1)
	assert.EqualValues(t, dash.FlavorNativeWindows, win.Candidates[0].Flavor)

	linux := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64"})
	require.Len(t, linux.Candidates, 1)
	assert.EqualValues(t, dash.FlavorNativeLinux, linux.Candidates[0].Flavor)

	// a host with a love runtime sees the payloads next to the natives
	rt := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "arm64", Runtimes: []dash.Flavor{dash.FlavorLove}})
	flavors := map[dash.Flavor]int{}
	for _, c := range rt.Candidates {
		flavors[c.Flavor]++
	}
	assert.EqualValues(t, 2, flavors[dash.FlavorLove])
}

func Test_Jar(t *testing.T) {
	_, m := configureEngine(t, "jar")
	m.expect(t, "gdx.jar", dash.FlavorJar, dash.EngineLibGDX, "")
	m.expect(t, "lwjgl.jar", dash.FlavorJar, dash.EngineLWJGL, "")
	m.expect(t, "plain.jar", dash.FlavorJar, "", "")
}

func Test_ProbeBudget(t *testing.T) {
	// a budget too small for the PE magic pass leaves nothing but the
	// name-driven payloads; nothing crashes
	_, m := configureEngine(t, "godot", dash.ConfigureParams{MaxProbeBytes: 16})
	assert.Nil(t, m["embedded/Game.exe"])
	// the pck header is 20 bytes: over budget too
	assert.Nil(t, m["game.pck"])

	_, m = configureEngine(t, "godot", dash.ConfigureParams{MaxProbeBytes: 4096})
	m.expect(t, "game.pck", dash.FlavorGodotPck, dash.EngineGodot, "4.2.1")
	m.expect(t, "embedded/Game.exe", dash.FlavorNativeWindows, dash.EngineGodot, "3.5.2")

	// once the magic pass has spent most of the budget, the full tail
	// window no longer fits, but a 12-byte trailer check still must
	_, m = configureEngine(t, "godot", dash.ConfigureParams{MaxProbeBytes: 150 << 10})
	m.expect(t, "bigembedded/game.x86_64#godot-pck", dash.FlavorGodotPck, dash.EngineGodot, "4.3.0")
}
