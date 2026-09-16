package dash

// Reference game pages used to verify this detector:
//   https://devolverdigital.itch.io/mcpixel-3
//     i386, amd64, arm64, arm, riscv64, FreeBSD and Haiku builds

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/itchio/spellbook"
	"github.com/itchio/wizardry/wizardry/wizutil"
)

var libraryPattern = regexp.MustCompile(`\.so(\.[0-9]+)*$`)

func sniffELF(r *probeReader, name string, size int64) (*Candidate, error) {
	if libraryPattern.MatchString(name) {
		// libraries (.so files) are not launch candidates
		return nil, nil
	}

	sr := wizutil.NewSliceReader(r, 0, size)
	spell := spellbook.Identify(sr, 0)

	if !spellHas(spell, "ELF") {
		// looked like ELF but isn't? weird
		return nil, nil
	}

	hdr := r.readHead(elf64HeaderLen)
	if elfIsSharedObject(r, hdr) {
		return nil, nil
	}

	result := &Candidate{
		Flavor:    FlavorNativeLinux,
		Spell:     spell,
		LinuxInfo: &LinuxInfo{},
	}

	result.Arch = elfHeaderArch(hdr)
	result.LinuxInfo.Arch = result.Arch
	result.LinuxInfo.OS = elfHeaderOS(hdr)
	result.LinuxInfo.ABI = elfHeaderABI(hdr)

	return result, nil
}

// elfHeaderLen covers e_flags in a 32-bit header (offset 0x24), which is
// all the arch, OS and ABI reads need.
const elfHeaderLen = 40

const (
	elf32HeaderLen = 52
	elf64HeaderLen = 64
	// caps so a bogus header can't drive a huge read
	maxProgramHeaders = 64
	maxDynamicScan    = 64 << 10
)

// elfIsSharedObject reports whether an ET_DYN file is loaded by another
// program rather than run. Position independent executables are ET_DYN too
// (node-webkit, most distro builds), but they carry a program interpreter.
// A static-pie has neither an interpreter nor dynamic dependencies, so only
// an ET_DYN with no PT_INTERP that names DT_NEEDED libraries is a library.
// Truncated or unreadable headers keep the file as a candidate.
func elfIsSharedObject(r *probeReader, hdr []byte) bool {
	if len(hdr) < 20 {
		return false
	}
	var order binary.ByteOrder = binary.LittleEndian
	if hdr[elf.EI_DATA] == byte(elf.ELFDATA2MSB) {
		order = binary.BigEndian
	}
	if elf.Type(order.Uint16(hdr[16:18])) != elf.ET_DYN {
		return false
	}

	is64 := hdr[elf.EI_CLASS] == byte(elf.ELFCLASS64)
	var phoff int64
	var phentsize, phnum int
	if is64 {
		if len(hdr) < elf64HeaderLen {
			return false
		}
		phoff = int64(order.Uint64(hdr[0x20:0x28]))
		phentsize = int(order.Uint16(hdr[0x36:0x38]))
		phnum = int(order.Uint16(hdr[0x38:0x3a]))
	} else {
		if len(hdr) < elf32HeaderLen {
			return false
		}
		phoff = int64(order.Uint32(hdr[0x1c:0x20]))
		phentsize = int(order.Uint16(hdr[0x2a:0x2c]))
		phnum = int(order.Uint16(hdr[0x2c:0x2e]))
	}
	if phnum == 0 || phnum > maxProgramHeaders || phentsize < 8 {
		return false
	}
	table := r.readAt(phoff, phentsize*phnum)
	if table == nil {
		return false
	}

	var dynOff, dynSize int64
	for i := 0; i < phnum; i++ {
		ph := table[i*phentsize : (i+1)*phentsize]
		switch elf.ProgType(order.Uint32(ph[0:4])) {
		case elf.PT_INTERP:
			return false
		case elf.PT_DYNAMIC:
			if is64 {
				if len(ph) < 40 {
					return false
				}
				dynOff = int64(order.Uint64(ph[8:16]))
				dynSize = int64(order.Uint64(ph[32:40]))
			} else {
				if len(ph) < 20 {
					return false
				}
				dynOff = int64(order.Uint32(ph[4:8]))
				dynSize = int64(order.Uint32(ph[16:20]))
			}
		}
	}
	if dynSize <= 0 || dynSize > maxDynamicScan {
		return false
	}
	dyn := r.readAt(dynOff, int(dynSize))
	if dyn == nil {
		return false
	}

	entrySize := 8
	if is64 {
		entrySize = 16
	}
	for off := 0; off+entrySize <= len(dyn); off += entrySize {
		var tag int64
		if is64 {
			tag = int64(order.Uint64(dyn[off : off+8]))
		} else {
			tag = int64(order.Uint32(dyn[off : off+4]))
		}
		switch elf.DynTag(tag) {
		case elf.DT_NULL:
			return false
		case elf.DT_NEEDED:
			return true
		}
	}
	return false
}

// ARM EABI float convention bits in e_flags
const (
	elfARMFloatSoft = 0x200
	elfARMFloatHard = 0x400
)

// elfHeaderABI names the float ABI of a 32-bit ARM executable. Other
// machines have no such split worth recording.
func elfHeaderABI(hdr []byte) string {
	if len(hdr) < elfHeaderLen || elfHeaderArch(hdr) != ArchArm {
		return ""
	}
	var order binary.ByteOrder = binary.LittleEndian
	if hdr[elf.EI_DATA] == byte(elf.ELFDATA2MSB) {
		order = binary.BigEndian
	}
	flags := order.Uint32(hdr[0x24:0x28])
	switch {
	case flags&elfARMFloatHard != 0:
		return "eabihf"
	case flags&elfARMFloatSoft != 0:
		return "eabi"
	}
	return ""
}

// elfHeaderArch reads e_machine, honoring the byte order declared in
// e_ident. The "64-bit" class token is not enough: aarch64 is 64-bit too.
func elfHeaderArch(hdr []byte) Arch {
	if len(hdr) < 20 {
		return ""
	}
	var order binary.ByteOrder = binary.LittleEndian
	if hdr[elf.EI_DATA] == byte(elf.ELFDATA2MSB) {
		order = binary.BigEndian
	}
	switch elf.Machine(order.Uint16(hdr[18:20])) {
	case elf.EM_386:
		return Arch386
	case elf.EM_X86_64:
		return ArchAmd64
	case elf.EM_AARCH64:
		return ArchArm64
	case elf.EM_ARM:
		return ArchArm
	case elf.EM_RISCV:
		if hdr[elf.EI_CLASS] == byte(elf.ELFCLASS64) {
			return ArchRiscv64
		}
		return ""
	default:
		return ""
	}
}

// elfHeaderOS reads EI_OSABI. Linux binaries leave it at System V, so only
// the BSDs are named here.
func elfHeaderOS(hdr []byte) string {
	if len(hdr) < 20 {
		return ""
	}
	switch elf.OSABI(hdr[elf.EI_OSABI]) {
	case elf.ELFOSABI_FREEBSD:
		return "freebsd"
	case elf.ELFOSABI_OPENBSD:
		return "openbsd"
	case elf.ELFOSABI_NETBSD:
		return "netbsd"
	}
	return ""
}

// probeELF fills the dependency record of a Linux candidate. It reads
// section tables and symbol versions, so it is not budgeted like sniffing.
func probeELF(ra io.ReaderAt, info *LinuxInfo) error {
	ef, err := elf.NewFile(ra)
	if err != nil {
		return err
	}
	defer ef.Close()

	info.Static = ef.SectionByType(elf.SHT_DYNAMIC) == nil

	libs, err := ef.ImportedLibraries()
	if err == nil {
		info.Imports = libs
	}
	// Haiku declares System V like Linux does; its C library gives it away
	if info.OS == "" && slices.Contains(libs, "libroot.so") {
		info.OS = "haiku"
	}

	info.Symbols = ef.Section(".symtab") != nil
	for _, p := range ef.Progs {
		if p.Type != elf.PT_INTERP || p.Filesz == 0 || p.Filesz > 256 {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err == nil {
			info.Interpreter = string(bytes.TrimRight(buf, "\x00"))
		}
		break
	}
	probeWindowing(ef, info)

	syms, err := ef.ImportedSymbols()
	if err != nil {
		return nil
	}
	for _, sym := range syms {
		if !strings.HasPrefix(sym.Version, "GLIBC_") {
			continue
		}
		ver := strings.TrimPrefix(sym.Version, "GLIBC_")
		if compareVersions(ver, info.GlibcVersion) > 0 {
			info.GlibcVersion = ver
		}
	}
	return nil
}

// Display libraries by the file names they are linked or dlopened by. A
// bundled SDL names the ones for every backend it was built with.
var displayLibraries = []struct{ prefix, tag string }{
	{"libX11.so", "x11"},
	{"libwayland-client.so", "wayland"},
	{"libgbm.so", "kmsdrm"},
	{"libglfw.so", "glfw"},
	{"libEGL.so", "egl"},
	{"libGL.so", "gl"},
	{"libGLESv2.so", "gles"},
	{"libvulkan.so", "vulkan"},
}

// Read-only data larger than this is not searched for library names.
const maxRodataScan = 256 << 20

// probeWindowing records how the executable reaches a display: the SDL
// it imports or bundles, and the display libraries it names. A bundled
// SDL shows in the strings it keeps for its own use: the name of the
// dynamic API variable, or its video driver hint without it.
func probeWindowing(ef *elf.File, info *LinuxInfo) {
	found := map[string]bool{}
	for _, lib := range info.Imports {
		switch {
		case strings.HasPrefix(lib, "libSDL2-2.0.so"):
			info.SDL = "2"
		case strings.HasPrefix(lib, "libSDL3.so"):
			info.SDL = "3"
		}
		for _, d := range displayLibraries {
			if strings.HasPrefix(lib, d.prefix) {
				found[d.tag] = true
			}
		}
	}

	var data []byte
	if s := ef.Section(".rodata"); s != nil && s.Size <= maxRodataScan {
		data, _ = s.Data()
	}
	has := func(needle string) bool { return bytes.Contains(data, []byte(needle)) }
	for _, d := range displayLibraries {
		if has(d.prefix) {
			found[d.tag] = true
		}
	}
	if info.SDL == "" {
		switch {
		case has("SDL_DYNAMIC_API"):
			info.SDL, info.SDLBundled, info.SDLDynamicAPI = "2", true, true
		case has("SDL3_DYNAMIC_API"):
			info.SDL, info.SDLBundled, info.SDLDynamicAPI = "3", true, true
		case has("SDL_VIDEODRIVER"):
			info.SDL, info.SDLBundled = "2", true
		case has("SDL_VIDEO_DRIVER"):
			info.SDL, info.SDLBundled = "3", true
		}
	}

	for tag := range found {
		info.Display = append(info.Display, tag)
	}
	sort.Strings(info.Display)
}

// ProbeELF returns the full Linux record for one executable: what the
// magic pass reads from the header plus what DeepProbe adds. It is for
// tools that look at a single file rather than an install folder.
func ProbeELF(r io.ReadSeeker) (*LinuxInfo, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	hdr := make([]byte, elfHeaderLen)
	if n, err := io.ReadFull(r, hdr); err != nil && n < 20 {
		return nil, err
	}
	info := &LinuxInfo{Arch: elfHeaderArch(hdr), OS: elfHeaderOS(hdr), ABI: elfHeaderABI(hdr)}
	if err := probeELF(&readerAtFromSeeker{r}, info); err != nil {
		return nil, err
	}
	return info, nil
}
