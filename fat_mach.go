package dash

import (
	"encoding/binary"
	"io"

	"github.com/itchio/spellbook"
	"github.com/itchio/wizardry/wizardry/wizutil"
)

// Mach-O cputype values, see <mach/machine.h>
const (
	machCpuArch64 = 0x01000000
	machCpuX86    = 7
	machCpuArm    = 12
)

func sniffFatMach(r *probeReader, size int64) (*Candidate, error) {
	var ra io.ReaderAt = r

	sr := wizutil.NewSliceReader(ra, 0, size)
	spell := spellbook.Identify(sr, 0)

	if spellHas(spell, "compiled Java class data,") {
		// nevermind
		return nil, nil
	}

	result := &Candidate{
		Flavor: FlavorNativeMacos,
		Spell:  spell,
	}
	result.Arch, result.MacosInfo = fatMachArch(ra)
	return result, nil
}

func sniffMachO(r *probeReader, size int64) (*Candidate, error) {
	var ra io.ReaderAt = r

	sr := wizutil.NewSliceReader(ra, 0, size)
	spell := spellbook.Identify(sr, 0)

	result := &Candidate{
		Flavor: FlavorNativeMacos,
		Spell:  spell,
	}
	result.Arch, result.MacosInfo = thinMachArch(ra)
	return result, nil
}

// thinMachArch reads the cputype from a Mach-O header. Only the little-endian
// magics (0xCEFAEDFE, 0xCFFAEDFE) are handled, matching what doSniff accepts.
func thinMachArch(ra io.ReaderAt) (Arch, *MacosInfo) {
	var buf [8]byte
	if _, err := ra.ReadAt(buf[:], 0); err != nil {
		return "", nil
	}

	arch := machCpuTypeToArch(binary.LittleEndian.Uint32(buf[4:8]))
	if arch == "" {
		return "", nil
	}
	return arch, &MacosInfo{Architectures: []Arch{arch}}
}

// fatMachArch reads the fat_arch table of a universal binary. The header is
// always big-endian regardless of the contained architectures.
func fatMachArch(ra io.ReaderAt) (Arch, *MacosInfo) {
	var hdr [8]byte
	if _, err := ra.ReadAt(hdr[:], 0); err != nil {
		return "", nil
	}
	nfat := binary.BigEndian.Uint32(hdr[4:8])
	// cap to something sane so a corrupt header can't make us read forever
	if nfat > 32 {
		return "", nil
	}

	var archs []Arch
	seen := make(map[Arch]bool)
	var entry [20]byte
	for i := uint32(0); i < nfat; i++ {
		if _, err := ra.ReadAt(entry[:], int64(8+i*20)); err != nil {
			break
		}
		arch := machCpuTypeToArch(binary.BigEndian.Uint32(entry[0:4]))
		if arch == "" || seen[arch] {
			continue
		}
		seen[arch] = true
		archs = append(archs, arch)
	}

	switch len(archs) {
	case 0:
		return "", nil
	case 1:
		return archs[0], &MacosInfo{Architectures: archs}
	default:
		return ArchUniversal, &MacosInfo{Architectures: archs}
	}
}

func machCpuTypeToArch(cputype uint32) Arch {
	switch cputype {
	case machCpuX86:
		return Arch386
	case machCpuX86 | machCpuArch64:
		return ArchAmd64
	case machCpuArm | machCpuArch64:
		return ArchArm64
	default:
		return ""
	}
}
