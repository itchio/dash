package dash

// Reference game pages used to verify this detector:
//   https://devolverdigital.itch.io/mcpixel-3
//     i386, amd64, arm64, arm, riscv64, FreeBSD and Haiku builds

import (
	"debug/elf"
	"encoding/binary"
	"io"
	"regexp"
	"slices"
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

	// some objects are marked as 'executable', others are marked
	// as 'shared objects', but it doesn't matter since executables
	// can be marked as shared objects as well (node-webkit) for example.

	result := &Candidate{
		Flavor:    FlavorNativeLinux,
		Spell:     spell,
		LinuxInfo: &LinuxInfo{},
	}

	hdr := r.readHead(20)
	result.Arch = elfHeaderArch(hdr)
	result.LinuxInfo.Arch = result.Arch
	result.LinuxInfo.OS = elfHeaderOS(hdr)

	return result, nil
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
