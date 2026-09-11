package dash

import (
	"bytes"
	"regexp"
	"strings"
)

// romDetector finds console ROMs and disc images by extension, then checks
// the system's header where the format has one. Formats without a header
// are trusted on extension alone, flagged, and capped at the largest
// cartridge the system ever shipped. ".md" is only accepted with the SEGA
// header, since it is also Markdown; ".bin" only with a Sega header.
//
// Details: "system" (nes, snes, gb, gbc, gba, nds, md, 32x, sms, gg, pce,
// lynx, ngp, a26, c64, amiga, n64, psx, ps2, psp, saturn, segacd,
// dreamcast, or "" for a disc image whose system could not be read),
// "confidence" ("ext" when the header was absent or not checked),
// "format" (for disc images: "cue", "iso", "chd").
type romDetector struct{}

// romCheck inspects a file and returns the system, whether the header
// confirmed it, and whether the file is a ROM at all.
type romCheck func(s *scan, index int, ext string) (system string, confirmed bool, ok bool)

var romExts = map[string]romCheck{
	".nes": checkNES,
	".sfc": checkSNES,
	".smc": checkSNES,
	".gb":  checkGameBoy,
	".gbc": checkGameBoy,
	".gba": checkGBA,
	".nds": checkNDS,
	".md":  checkMegaDrive,
	".gen": checkMegaDrive,
	".32x": checkMegaDrive,
	".bin": checkSegaBin,
	".sms": checkMasterSystem,
	".gg":  checkMasterSystem,
	".pce": extOnly("pce"),
	".lnx": checkLynx,
	".ngp": checkNeoGeoPocket,
	".ngc": checkNeoGeoPocket,
	".a26": extOnly("a26"),
	".d64": checkD64,
	".prg": extOnly("c64"),
	".t64": checkT64,
	".adf": checkADF,
	".z64": checkN64,
	".n64": checkN64,
	".v64": checkN64,
	".cue": checkCue,
	".iso": checkISO,
	".chd": checkCHD,
}

func (romDetector) detect(s *scan) error {
	for index, lower := range s.lowerFiles {
		ext := getExt(lower)
		check, ok := romExts[ext]
		if !ok {
			continue
		}
		system, confirmed, isROM := check(s, index, ext)
		if !isROM {
			continue
		}
		info := &EngineInfo{Engine: EngineROM}
		info.detail("system", system)
		if !confirmed {
			info.detail("confidence", "ext")
		}
		switch ext {
		case ".cue", ".iso", ".chd":
			info.detail("format", ext[1:])
		}
		s.addFileCandidate(index, FlavorROM, info)
	}
	return nil
}

// extOnlyMaxSize caps extension-only ROMs so a stray file with the same
// extension is not mistaken for a cartridge.
var extOnlyMaxSize = map[string]int64{
	"pce":   4 << 20,
	"a26":   64 << 10,
	"c64":   256 << 10,
	"snes":  8 << 20,
	"md":    8 << 20,
	"32x":   8 << 20,
	"sms":   1 << 20,
	"gg":    1 << 20,
	"lynx":  2 << 20,
	"amiga": 2 << 20,
}

func extOnlyOK(s *scan, index int, system string) bool {
	max, ok := extOnlyMaxSize[system]
	return !ok || s.container.Files[index].Size <= max
}

func extOnly(system string) romCheck {
	return func(s *scan, index int, _ string) (string, bool, bool) {
		return system, false, extOnlyOK(s, index, system)
	}
}

func checkNES(s *scan, index int, _ string) (string, bool, bool) {
	head := s.readHead(index, 4)
	if string(head) == "NES\x1a" {
		return "nes", true, true
	}
	return "", false, false
}

// checkSNES looks for the checksum complement at the LoROM or HiROM header
// location, skipping a 512-byte copier header when the size betrays one.
func checkSNES(s *scan, index int, _ string) (string, bool, bool) {
	size := s.container.Files[index].Size
	var skip int64
	if size%1024 == 512 {
		skip = 512
	}
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	for _, off := range []int64{0x7fdc, 0xffdc} {
		b := r.readAt(skip+off, 4)
		if b == nil {
			continue
		}
		complement := uint16(b[0]) | uint16(b[1])<<8
		checksum := uint16(b[2]) | uint16(b[3])<<8
		if complement^checksum == 0xffff {
			return "snes", true, true
		}
	}
	return "snes", false, extOnlyOK(s, index, "snes")
}

var nintendoLogoHead = []byte{0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b}

func checkGameBoy(s *scan, index int, ext string) (string, bool, bool) {
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	if !bytes.Equal(r.readAt(0x104, 8), nintendoLogoHead) {
		return "", false, false
	}
	system := "gb"
	if flag := r.readAt(0x143, 1); flag != nil && flag[0]&0x80 != 0 {
		system = "gbc"
	} else if ext == ".gbc" {
		system = "gbc"
	}
	return system, true, true
}

var gbaLogoHead = []byte{0x24, 0xff, 0xae, 0x51, 0x69, 0x9a, 0xa2, 0x21}

func checkGBA(s *scan, index int, _ string) (string, bool, bool) {
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	if bytes.Equal(r.readAt(0x04, 8), gbaLogoHead) {
		return "gba", true, true
	}
	return "", false, false
}

func checkNDS(s *scan, index int, _ string) (string, bool, bool) {
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	if bytes.Equal(r.readAt(0xc0, 8), gbaLogoHead) {
		return "nds", true, true
	}
	return "", false, false
}

func checkMegaDrive(s *scan, index int, ext string) (string, bool, bool) {
	system := "md"
	if ext == ".32x" {
		system = "32x"
	}
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	hdr := r.readAt(0x100, 16)
	if hdr == nil || !bytes.HasPrefix(hdr, []byte("SEGA")) {
		if ext == ".md" {
			return "", false, false
		}
		return system, false, extOnlyOK(s, index, system)
	}
	if bytes.Contains(hdr, []byte("32X")) {
		system = "32x"
	}
	return system, true, true
}

// checkSegaBin accepts a .bin only when it carries a Mega Drive or Master
// System header; the extension alone means nothing.
func checkSegaBin(s *scan, index int, _ string) (string, bool, bool) {
	if system, ok, _ := checkMegaDrive(s, index, ".bin"); ok {
		return system, true, true
	}
	if system, ok, _ := checkMasterSystem(s, index, ".bin"); ok {
		return system, true, true
	}
	return "", false, false
}

func checkMasterSystem(s *scan, index int, ext string) (string, bool, bool) {
	system := "sms"
	if ext == ".gg" {
		system = "gg"
	}
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	for _, off := range []int64{0x7ff0, 0x3ff0, 0x1ff0} {
		if string(r.readAt(off, 8)) == "TMR SEGA" {
			return system, true, true
		}
	}
	if ext == ".bin" {
		return "", false, false
	}
	return system, false, extOnlyOK(s, index, system)
}

func checkLynx(s *scan, index int, _ string) (string, bool, bool) {
	if string(s.readHead(index, 4)) == "LYNX" {
		return "lynx", true, true
	}
	return "lynx", false, extOnlyOK(s, index, "lynx")
}

func checkNeoGeoPocket(s *scan, index int, _ string) (string, bool, bool) {
	head := s.readHead(index, 28)
	if bytes.HasSuffix(head, []byte("SNK CORPORATION")) {
		return "ngp", true, true
	}
	return "", false, false
}

// checkD64 accepts the standard 35 and 40 track disk sizes, with and
// without error bytes.
func checkD64(s *scan, index int, _ string) (string, bool, bool) {
	switch s.container.Files[index].Size {
	case 174848, 175531, 196608, 197376:
		return "c64", true, true
	}
	return "c64", false, extOnlyOK(s, index, "c64")
}

func checkT64(s *scan, index int, _ string) (string, bool, bool) {
	head := s.readHead(index, 32)
	if bytes.HasPrefix(head, []byte("C64")) {
		return "c64", true, true
	}
	return "", false, false
}

// checkADF looks for an AmigaDOS boot block; NDOS or blank disks have none.
func checkADF(s *scan, index int, _ string) (string, bool, bool) {
	head := s.readHead(index, 4)
	if len(head) == 4 && string(head[:3]) == "DOS" && head[3] < 8 {
		return "amiga", true, true
	}
	return "amiga", false, extOnlyOK(s, index, "amiga")
}

func checkN64(s *scan, index int, _ string) (string, bool, bool) {
	head := s.readHead(index, 4)
	switch string(head) {
	case "\x80\x37\x12\x40", "\x37\x80\x40\x12", "\x40\x12\x37\x80", "\x12\x40\x80\x37":
		return "n64", true, true
	}
	return "", false, false
}

var cueFilePattern = regexp.MustCompile(`(?im)^\s*FILE\s+"([^"]+)"|^\s*FILE\s+(\S+)`)

// checkCue reads the first FILE entry of a cue sheet and identifies the
// system from the first sector of that track.
func checkCue(s *scan, index int, _ string) (string, bool, bool) {
	head := s.readHead(index, 4096)
	m := cueFilePattern.FindSubmatch(head)
	if m == nil {
		return "", false, false
	}
	name := string(m[1])
	if name == "" {
		name = string(m[2])
	}
	name = strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	binIndex, ok := s.file(joinPath(parentDir(s.lowerFiles[index]), name))
	if !ok {
		return "", false, false
	}
	r, err := s.open(binIndex)
	if err != nil {
		return "", false, false
	}
	// raw 2352-byte sectors: 12 sync + 4 header, then 8 more for mode 2
	for _, off := range []int64{16, 24, 0} {
		if system := discSystem(r.readAt(off, 64)); system != "" {
			return system, true, true
		}
	}
	return "", false, false
}

func checkISO(s *scan, index int, _ string) (string, bool, bool) {
	r, err := s.open(index)
	if err != nil {
		return "", false, false
	}
	if system := discSystem(r.readAt(0, 64)); system != "" {
		return system, true, true
	}
	// primary volume descriptor at sector 16
	pvd := r.readAt(0x8000, 40)
	if pvd == nil || string(pvd[1:6]) != "CD001" {
		return "", false, false
	}
	sysID := strings.TrimSpace(string(pvd[8:40]))
	switch {
	case strings.HasPrefix(sysID, "PSP GAME"):
		return "psp", true, true
	case strings.HasPrefix(sysID, "PLAYSTATION"):
		// PS1 discs carry the license text in the system area, checked above
		return "ps2", true, true
	}
	return "", false, false
}

// discSystem recognizes the system area text at the start of a disc.
func discSystem(sector []byte) string {
	switch {
	case bytes.Contains(sector, []byte("Sony Computer Entertainment")):
		return "psx"
	case bytes.HasPrefix(sector, []byte("SEGA SEGASATURN")):
		return "saturn"
	case bytes.HasPrefix(sector, []byte("SEGADISCSYSTEM")):
		return "segacd"
	case bytes.HasPrefix(sector, []byte("SEGA SEGAKATANA")):
		return "dreamcast"
	}
	return ""
}

// checkCHD accepts the container without opening it: hunks are compressed
// and the system would need a decompression pass.
func checkCHD(s *scan, index int, _ string) (string, bool, bool) {
	if string(s.readHead(index, 8)) == "MComprHD" {
		return "", false, true
	}
	return "", false, false
}
