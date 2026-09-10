package dash

import (
	"debug/elf"
	"encoding/binary"
	"io"
	"regexp"

	"github.com/itchio/spellbook"
	"github.com/itchio/wizardry/wizardry/wizutil"
)

var libraryPattern = regexp.MustCompile(`\.so(\.[0-9]+)*$`)

func sniffELF(r io.ReadSeeker, name string, size int64) (*Candidate, error) {
	if libraryPattern.MatchString(name) {
		// libraries (.so files) are not launch candidates
		return nil, nil
	}

	ra := &readerAtFromSeeker{r}
	sr := wizutil.NewSliceReader(ra, 0, size)
	spell := spellbook.Identify(sr, 0)

	if !spellHas(spell, "ELF") {
		// looked like ELF but isn't? weird
		return nil, nil
	}

	// some objects are marked as 'executable', others are marked
	// as 'shared objects', but it doesn't matter since executables
	// can be marked as shared objects as well (node-webkit) for example.

	result := &Candidate{
		Flavor: FlavorNativeLinux,
		Spell:  spell,
	}

	var hdr [20]byte
	if n, _ := ra.ReadAt(hdr[:], 0); n == len(hdr) {
		result.Arch = elfHeaderArch(hdr[:])
	}

	return result, nil
}

// elfHeaderArch reads e_machine, honoring the byte order declared in
// e_ident. The "64-bit" class token is not enough: aarch64 is 64-bit too.
func elfHeaderArch(hdr []byte) Arch {
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
	default:
		return ""
	}
}
