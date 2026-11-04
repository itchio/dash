package dash

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/itchio/headway/state"
	"github.com/itchio/pelican"
	"github.com/stretchr/testify/assert"
)

func testConsumer(t *testing.T) *state.Consumer {
	return &state.Consumer{OnMessage: func(lvl, msg string) {
		t.Helper()
		t.Logf("[%s] %s", lvl, msg)
	}}
}

const (
	testRsrcVA  = 0x1000
	testRsrcOff = 0x200
)

type testSection struct {
	name string
	data []byte
}

// buildPE makes a minimal PE32 image with a .rsrc section holding rsrc,
// then any extra sections, followed by overlay.
func buildPE(rsrc []byte, overlay []byte, extra ...testSection) []byte {
	le := binary.LittleEndian
	sections := append([]testSection{{".rsrc", rsrc}}, extra...)

	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	// e_lfarlc >= 0x40 is how spellbook tells PE from plain DOS images
	dos[0x18] = 0x40
	le.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)

	b.WriteString("PE\x00\x00")
	coff := make([]byte, 20)
	le.PutUint16(coff[0:], 0x14c)
	le.PutUint16(coff[2:], uint16(len(sections)))
	le.PutUint16(coff[16:], 224)
	le.PutUint16(coff[18:], 0x0102)
	b.Write(coff)

	opt := make([]byte, 224)
	le.PutUint16(opt[0:], 0x10b)
	le.PutUint32(opt[92:], 16)
	if len(rsrc) > 0 {
		le.PutUint32(opt[96+2*8:], testRsrcVA)
		le.PutUint32(opt[96+2*8+4:], uint32(len(rsrc)))
	}
	b.Write(opt)

	raw, va := uint32(testRsrcOff), uint32(testRsrcVA)
	for _, s := range sections {
		sec := make([]byte, 40)
		copy(sec, s.name)
		le.PutUint32(sec[8:], uint32(len(s.data)))
		le.PutUint32(sec[12:], va)
		le.PutUint32(sec[16:], uint32(len(s.data)))
		le.PutUint32(sec[20:], raw)
		b.Write(sec)
		raw += uint32(len(s.data))
		va += 0x100000
	}

	b.Write(make([]byte, testRsrcOff-b.Len()))
	for _, s := range sections {
		b.Write(s.data)
	}
	b.Write(overlay)
	return b.Bytes()
}

func buildCab(names ...string) []byte {
	var files bytes.Buffer
	for _, n := range names {
		files.Write(make([]byte, 16))
		files.WriteString(n)
		files.WriteByte(0)
	}
	hdr := make([]byte, 36)
	copy(hdr, "MSCF")
	binary.LittleEndian.PutUint32(hdr[8:], uint32(36+8+files.Len()))
	binary.LittleEndian.PutUint32(hdr[16:], 36+8)
	hdr[24], hdr[25] = 3, 1
	binary.LittleEndian.PutUint16(hdr[26:], 1)
	binary.LittleEndian.PutUint16(hdr[28:], uint16(len(names)))
	out := append(hdr, make([]byte, 8)...)
	return append(out, files.Bytes()...)
}

// buildResource lays out <typeID>/<name>/<lang> pointing at data. An
// empty name makes an integer id 1 entry, as manifests use.
func buildResource(typeID uint32, name string, data []byte) []byte {
	le := binary.LittleEndian
	dir := func(named, ids int, nameOrID, target uint32) []byte {
		d := make([]byte, 24)
		le.PutUint16(d[12:], uint16(named))
		le.PutUint16(d[14:], uint16(ids))
		le.PutUint32(d[16:], nameOrID)
		le.PutUint32(d[20:], target)
		return d
	}
	const nameStr, dataOff = 0x58, 0x80
	var r []byte
	r = append(r, dir(0, 1, typeID, 0x80000000|0x18)...)
	if name == "" {
		r = append(r, dir(0, 1, 1, 0x80000000|0x30)...)
	} else {
		r = append(r, dir(1, 0, 0x80000000|nameStr, 0x80000000|0x30)...)
	}
	r = append(r, dir(0, 1, 0x409, 0x48)...)
	entry := make([]byte, 16)
	le.PutUint32(entry[0:], testRsrcVA+dataOff)
	le.PutUint32(entry[4:], uint32(len(data)))
	r = append(r, entry...)
	r = le.AppendUint16(r, uint16(len(name)))
	r = append(r, utf16le(name)...)
	r = append(r, make([]byte, dataOff-len(r))...)
	return append(r, data...)
}

func buildIExpressRsrc(name string, cab []byte) []byte {
	return buildResource(uint32(pelican.ResourceTypeRcData), name, cab)
}

func sniffBytes(t *testing.T, b []byte) *Candidate {
	t.Helper()
	c, err := Sniff(bytes.NewReader(b), "game.exe", int64(len(b)))
	assert.NoError(t, err)
	if !assert.NotNil(t, c) || !assert.NotNil(t, c.WindowsInfo) {
		t.FailNow()
	}
	return c
}

func Test_WindowsInstallerOverlays(t *testing.T) {
	payload := bytes.Repeat([]byte{0xaa}, 256)
	nsisHeader := append([]byte{0, 0, 0, 0}, nsisMagic...)

	cases := []struct {
		name    string
		overlay []byte
		want    WindowsInstallerType
	}{
		{"inno", append([]byte("zlb\x1a"), payload...), WindowsInstallerTypeInno},
		{"nsis", append(nsisHeader, payload...), WindowsInstallerTypeNullsoft},
		{"7zip", append(sevenZipMagic, payload...), WindowsInstallerTypeSevenZip},
		{"7zip with config", append([]byte(";!@Install@!UTF-8!\nTitle=\"x\"\n"), payload...), WindowsInstallerTypeSevenZip},
		{"rar", append([]byte("Rar!\x1a\x07\x01\x00"), payload...), WindowsInstallerTypeWinRAR},
		{"winrar x64 messages", append(winrarMessages, payload...), WindowsInstallerTypeWinRAR},
		{"clickteam", append([]byte("wwgT)H5\x14"), payload...), WindowsInstallerTypeClickteam},
		{"cab", buildCab("Game.exe", "Data/Map001.rvdata"), WindowsInstallerTypeCab},
		// appended data that is the game itself, not an installer
		{"fused zip", append([]byte("PK\x03\x04"), payload...), ""},
		{"clickteam fusion", append([]byte("wwwwI\x87G\x12"), payload...), ""},
		{"no overlay", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sniffBytes(t, buildPE(make([]byte, 0x200), tc.overlay))
			assert.EqualValues(t, tc.want, c.WindowsInfo.InstallerType)
		})
	}
}

func Test_WindowsInstallerCabEngines(t *testing.T) {
	c := sniffBytes(t, buildPE(make([]byte, 0x200), buildCab("Game.exe", "Game.rgss3a", "Game.ini")))
	assert.EqualValues(t, WindowsInstallerTypeCab, c.WindowsInfo.InstallerType)
	if assert.NotNil(t, c.Engine) {
		assert.EqualValues(t, EngineRPGMaker, c.Engine.Engine)
		assert.Equal(t, "cab", c.Engine.Details["packager"])
	}
}

func Test_WindowsInstallerWinRARZip(t *testing.T) {
	zip := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0xaa}, 64)...)
	manifest := []byte(`<assembly><description>WinRAR SFX module</description></assembly>`)

	c := sniffBytes(t, buildPE(buildResource(uint32(pelican.ResourceTypeManifest), "", manifest), zip))
	assert.EqualValues(t, WindowsInstallerTypeWinRAR, c.WindowsInfo.InstallerType)

	other := []byte(`<assembly><description>LÖVE</description></assembly>`)
	c = sniffBytes(t, buildPE(buildResource(uint32(pelican.ResourceTypeManifest), "", other), zip))
	assert.EqualValues(t, "", c.WindowsInfo.InstallerType)
}

func Test_WindowsInstallerRPGMakerStub(t *testing.T) {
	rdata := append(make([]byte, 32), utf16le(`Software\Enterbrain\RPGVX2`)...)
	cab := buildCab(`Audio\BGM\Battle1.ogg`, `Data\Map001.rvdata2`)
	c := sniffBytes(t, buildPE(make([]byte, 0x200), cab, testSection{".rdata", rdata}))
	assert.EqualValues(t, WindowsInstallerTypeCab, c.WindowsInfo.InstallerType)
	if assert.NotNil(t, c.Engine) {
		assert.EqualValues(t, EngineRPGMaker, c.Engine.Engine)
	}

	c = sniffBytes(t, buildPE(make([]byte, 0x200), cab, testSection{".rdata", make([]byte, 64)}))
	assert.EqualValues(t, WindowsInstallerTypeCab, c.WindowsInfo.InstallerType)
	assert.Nil(t, c.Engine)
}

func Test_WindowsInstallerIExpress(t *testing.T) {
	t.Run("gamemaker single runtime executable", func(t *testing.T) {
		rsrc := buildIExpressRsrc("CABINET", buildCab("D3DX9_43.dll", "data.win", "Messing Around.exe"))
		c := sniffBytes(t, buildPE(rsrc, nil))
		assert.EqualValues(t, WindowsInstallerTypeIExpress, c.WindowsInfo.InstallerType)
		if assert.NotNil(t, c.Engine) {
			assert.EqualValues(t, EngineGameMaker, c.Engine.Engine)
			assert.Equal(t, "iexpress", c.Engine.Details["packager"])
		}
	})

	t.Run("plain package", func(t *testing.T) {
		rsrc := buildIExpressRsrc("CABINET", buildCab("setup.inf", "game.exe"))
		c := sniffBytes(t, buildPE(rsrc, nil))
		assert.EqualValues(t, WindowsInstallerTypeIExpress, c.WindowsInfo.InstallerType)
		assert.Nil(t, c.Engine)
	})

	t.Run("other rcdata name", func(t *testing.T) {
		rsrc := buildIExpressRsrc("PAYLOAD", buildCab("data.win"))
		c := sniffBytes(t, buildPE(rsrc, nil))
		assert.EqualValues(t, "", c.WindowsInfo.InstallerType)
	})
}

func Test_WindowsInstallerMalformed(t *testing.T) {
	pe := buildPE(buildIExpressRsrc("CABINET", buildCab("data.win")), nil)

	// every truncation must sniff without panicking
	for n := 0x40; n < len(pe); n += 7 {
		_, err := Sniff(bytes.NewReader(pe[:n]), "game.exe", int64(n))
		assert.NoError(t, err)
	}

	// a cabinet claiming far more files than it has
	cab := buildCab("a", "b")
	binary.LittleEndian.PutUint16(cab[28:], 0xffff)
	c := sniffBytes(t, buildPE(make([]byte, 0x200), cab))
	assert.EqualValues(t, WindowsInstallerTypeCab, c.WindowsInfo.InstallerType)
}

func Test_WindowsInstallerArchFromHeader(t *testing.T) {
	c := sniffBytes(t, buildPE(make([]byte, 0x200), nil))
	assert.EqualValues(t, Arch386, c.Arch)
}

func Test_WindowsInstallerIgnoresUndeclaredDataDirectories(t *testing.T) {
	pe := buildPE(buildIExpressRsrc("CABINET", buildCab("data.win")), nil)
	// NumberOfRvaAndSizes sits 92 bytes into the optional header
	binary.LittleEndian.PutUint32(pe[0x40+4+20+92:], 2)
	c := sniffBytes(t, pe)
	assert.EqualValues(t, "", c.WindowsInfo.InstallerType)
}

func Test_ConfigureKeepsGameMakerPackage(t *testing.T) {
	dir := t.TempDir()
	game := buildPE(buildIExpressRsrc("CABINET", buildCab("data.win", "Game.exe")), nil)
	setup := buildPE(make([]byte, 0x200), buildCab("Game.exe", "Data/Map001.rvdata"))
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "game.exe"), game, 0o644))
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "setup.exe"), setup, 0o644))

	v, err := Configure(context.Background(), dir, ConfigureParams{Consumer: testConsumer(t)})
	assert.NoError(t, err)
	assert.Len(t, v.Candidates, 2)

	w := v.Filter(testConsumer(t), FilterParams{OS: "windows", Arch: "386"})
	if assert.Len(t, w.Candidates, 1) {
		assert.Equal(t, "game.exe", w.Candidates[0].Path)
	}
}

func Test_WindowsInstallerArchWithoutSections(t *testing.T) {
	pe := buildPE(make([]byte, 0x200), nil)
	binary.LittleEndian.PutUint16(pe[0x40+4+2:], 0)
	c := sniffBytes(t, pe)
	assert.EqualValues(t, Arch386, c.Arch)
	assert.EqualValues(t, "", c.WindowsInfo.InstallerType)
}

func Test_InstallerLaunchesGame(t *testing.T) {
	iexpress := func(engine *EngineInfo) *Candidate {
		return &Candidate{WindowsInfo: &WindowsInfo{InstallerType: WindowsInstallerTypeIExpress}, Engine: engine}
	}
	fromCab := &EngineInfo{Engine: EngineGameMaker}
	fromCab.detail("packager", "iexpress")
	assert.True(t, iexpress(fromCab).installerLaunchesGame())

	// annotated by a data.win next to it, not by its own cabinet
	assert.False(t, iexpress(&EngineInfo{Engine: EngineGameMaker}).installerLaunchesGame())
	rpg := &EngineInfo{Engine: EngineRPGMaker}
	rpg.detail("packager", "iexpress")
	assert.False(t, iexpress(rpg).installerLaunchesGame())
	assert.False(t, (&Candidate{WindowsInfo: &WindowsInfo{InstallerType: WindowsInstallerTypeCab}, Engine: fromCab}).installerLaunchesGame())
}

func Test_SpellInstallerType(t *testing.T) {
	cases := map[string]WindowsInstallerType{
		"\\b, InnoSetup installer":                        WindowsInstallerTypeInno,
		"\\b, Nullsoft Installer self-extracting archive": WindowsInstallerTypeNullsoft,
		"\\b, RAR self-extracting archive":                WindowsInstallerTypeWinRAR,
		"\\b, ZIP self-extracting archive (WinZip)":       WindowsInstallerTypeArchive,
		"\\b, ZIP self-extracting archive (Info-Zip)":     WindowsInstallerTypeArchive,
		"\\b, InstallShield self-extracting archive":      WindowsInstallerTypeArchive,
		"\\b, UPX compressed":                             "",
	}
	for token, want := range cases {
		assert.EqualValues(t, want, spellInstallerType([]string{"PE", token}), token)
	}
}

func Test_WindowsInstallerArchSurvivesUnreadableStringTable(t *testing.T) {
	pe := buildPE(make([]byte, 0x200), nil)
	table := len(pe)
	pe = append(pe, make([]byte, peProbeBytes+(1<<20))...)
	binary.LittleEndian.PutUint32(pe[table:], uint32(len(pe)-table))
	// PointerToSymbolTable: the string table follows a symbol table of 0 entries
	binary.LittleEndian.PutUint32(pe[0x40+4+8:], uint32(table))
	// arm64, which spellbook's 32/32+ tokens cannot stand in for
	binary.LittleEndian.PutUint16(pe[0x40+4:], 0xaa64)

	c := sniffBytes(t, pe)
	assert.EqualValues(t, ArchArm64, c.Arch)
}
