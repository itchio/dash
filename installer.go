package dash

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/itchio/pelican"
	"github.com/itchio/pelican/pe"
)

// peProbeBytes bounds what the PE header parse and the installer sniff may
// read of one file: headers, the start of the overlay, a cabinet file table
// and a slice of .rdata. It is separate from the shared per-file budget so
// spellbook's scans can neither starve it nor be starved by it.
const peProbeBytes = 192 << 10

var (
	sevenZipMagic     = []byte("7z\xbc\xaf\x27\x1c")
	sevenZipSfxConfig = []byte(";!@Install@!UTF-8!")
	rarMagic          = []byte("Rar!\x1a\x07")
	// 64-bit WinRAR SFX modules put their UTF-16 message table before
	// the RAR archive
	winrarMessages = append([]byte{0xff, 0xfe}, utf16le("***messages***")...)
	winrarManifest = []byte("WinRAR SFX")
	zipMagic       = []byte("PK\x03\x04")
	cabMagic       = []byte("MSCF")
	// RPG Maker's "compress game data" stub remembers the extract folder
	// under this registry key
	rpgmakerRegistryKey = utf16le(`Software\Enterbrain\`)
	innoMagic           = []byte("zlb\x1a")
	nsisMagic           = []byte("\xef\xbe\xad\xdeNullsoftInst")
	// Clickteam Install Creator data block
	clickteamMagic = []byte("wwgT)H")
)

type installerSniff struct {
	installerType WindowsInstallerType
	engine        *EngineInfo
}

// sniffWindowsInstaller identifies installers and self-extracting archives
// by the data appended to their stub, or for IExpress by the cabinet in
// their resources. Every check matches the installer's own format, never
// just "has appended data": games ship that way too (fused LÖVE, Clickteam
// Fusion).
func sniffWindowsInstaller(f *pe.File) installerSniff {
	var res installerSniff

	if overlay, ok := f.Overlay(); ok {
		ov := readAt(f, overlay, 64)
		switch {
		case bytes.HasPrefix(ov, innoMagic):
			res.installerType = WindowsInstallerTypeInno
		case len(ov) >= 4+len(nsisMagic) && bytes.Equal(ov[4:4+len(nsisMagic)], nsisMagic):
			res.installerType = WindowsInstallerTypeNullsoft
		case bytes.HasPrefix(ov, sevenZipMagic), bytes.HasPrefix(ov, sevenZipSfxConfig):
			res.installerType = WindowsInstallerTypeSevenZip
		case bytes.HasPrefix(ov, rarMagic), bytes.HasPrefix(ov, winrarMessages):
			res.installerType = WindowsInstallerTypeWinRAR
		case bytes.HasPrefix(ov, zipMagic):
			// WinRAR also builds zip SFXes; a fused LÖVE or other game with
			// a zip appended has no WinRAR manifest
			if bytes.Contains(resourceHead(f, pelican.ResourceTypeManifest, "", 4<<10), winrarManifest) {
				res.installerType = WindowsInstallerTypeWinRAR
			}
		case bytes.HasPrefix(ov, clickteamMagic):
			res.installerType = WindowsInstallerTypeClickteam
		case bytes.HasPrefix(ov, cabMagic):
			res.installerType = WindowsInstallerTypeCab
			res.engine = cabPayloadEngine(res.installerType, cabFileNames(f, overlay))
			if res.engine == nil && bytes.Contains(sectionHead(f, ".rdata", 64<<10), rpgmakerRegistryKey) {
				res.engine = &EngineInfo{Engine: EngineRPGMaker}
				res.engine.detail("packager", string(res.installerType))
			}
		}
		if res.installerType != "" {
			return res
		}
	}

	if cab, ok := pelican.FindResource(f, pelican.ResourceTypeRcData, "CABINET"); ok {
		if bytes.Equal(readAt(f, cab.Offset, 4), cabMagic) {
			res.installerType = WindowsInstallerTypeIExpress
			res.engine = cabPayloadEngine(res.installerType, cabFileNames(f, cab.Offset))
		}
	}
	return res
}

// cabPayloadEngine recognizes engine exports that ship as a cabinet SFX:
// GameMaker Studio 1.x "single runtime executable" (IExpress) and RPG Maker
// XP/VX/VX Ace "compress game data" (stub + appended CAB).
func cabPayloadEngine(packager WindowsInstallerType, names []string) *EngineInfo {
	for _, name := range names {
		var engine Engine
		switch strings.ToLower(name[strings.LastIndexAny(name, `\/`)+1:]) {
		case "data.win":
			engine = EngineGameMaker
		case "game.rgssad", "game.rgss2a", "game.rgss3a":
			engine = EngineRPGMaker
		default:
			continue
		}
		info := &EngineInfo{Engine: engine}
		info.detail("packager", string(packager))
		return info
	}
	return nil
}

// readAt returns up to n bytes at off, or nil on any failure.
func readAt(f *pe.File, off int64, n int) []byte {
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, off)
	if got == 0 || (err != nil && err != io.EOF) {
		return nil
	}
	return buf[:got]
}

func sectionHead(f *pe.File, name string, limit int) []byte {
	s := f.Section(name)
	if s == nil {
		return nil
	}
	return readAt(f, int64(s.Offset), int(min(int64(s.Size), int64(limit))))
}

func resourceHead(f *pe.File, typ pelican.ResourceType, name string, limit int) []byte {
	r, ok := pelican.FindResource(f, typ, name)
	if !ok {
		return nil
	}
	return readAt(f, r.Offset, int(min(int64(r.Size), int64(limit))))
}

const (
	maxCabFiles     = 512
	cabFileListSize = 32 << 10
)

// cabFileNames lists the first entries of the cabinet at off. The file
// table sits right after the header and folder records, so it is cheap to
// read even when the cabinet is gigabytes long.
func cabFileNames(f *pe.File, off int64) []string {
	hdr := readAt(f, off, 36)
	if len(hdr) < 36 || !bytes.Equal(hdr[:4], cabMagic) {
		return nil
	}
	filesOff := int64(binary.LittleEndian.Uint32(hdr[16:20]))
	count := min(int(binary.LittleEndian.Uint16(hdr[28:30])), maxCabFiles)
	table := readAt(f, off+filesOff, cabFileListSize)
	var names []string
	pos := 0
	for range count {
		// cbFile, uoffFolderStart, iFolder, date, time, attribs, szName
		if pos+16 >= len(table) {
			break
		}
		end := bytes.IndexByte(table[pos+16:], 0)
		if end < 0 {
			break
		}
		names = append(names, string(table[pos+16:pos+16+end]))
		pos += 16 + end + 1
	}
	return names
}

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

// installerLaunchesGame is true for packages that are the game rather than
// a step before it: GameMaker Studio 1.x single runtime executables are
// IExpress packages that unpack to a temporary folder and run from there.
// Only the cabinet's own contents count; an engine annotation inherited
// from sibling files says nothing about what the package does.
func (c *Candidate) installerLaunchesGame() bool {
	return c.WindowsInfo != nil &&
		c.WindowsInfo.InstallerType == WindowsInstallerTypeIExpress &&
		c.Engine != nil && c.Engine.Engine == EngineGameMaker &&
		c.Engine.Details["packager"] == string(WindowsInstallerTypeIExpress)
}
