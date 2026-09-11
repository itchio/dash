package dash

import (
	"encoding/binary"

	"github.com/itchio/spellbook"
	"github.com/itchio/wizardry/wizardry/wizutil"
)

// PE machine types, see winnt.h
const (
	peMachineI386  = 0x14c
	peMachineAmd64 = 0x8664
	peMachineArm64 = 0xaa64
)

func sniffPE(r *probeReader, size int64) (*Candidate, error) {
	sr := wizutil.NewSliceReader(r, 0, size)
	spell := spellbook.Identify(sr, 0)

	if !spellHas(spell, "PE") {
		// uh oh
		return nil, nil
	}

	result := &Candidate{
		Flavor:      FlavorNativeWindows,
		Spell:       spell,
		WindowsInfo: &WindowsInfo{},
	}

	result.Arch = peMachineArch(r)
	if result.Arch == "" {
		if spellHas(spell, "\\b32 executable") {
			result.Arch = Arch386
		} else if spellHas(spell, "\\b32+ executable") {
			result.Arch = ArchAmd64
		}
	}
	result.WindowsInfo.Arch = result.Arch

	if spellHas(spell, "\\b, InnoSetup installer") {
		result.WindowsInfo.InstallerType = WindowsInstallerTypeInno
	} else if spellHas(spell, "\\b, InnoSetup uninstaller") {
		result.WindowsInfo.InstallerType = WindowsInstallerTypeInno
		result.WindowsInfo.Uninstaller = true
	} else if spellHas(spell, "\\b, Nullsoft Installer self-extracting archive") {
		result.WindowsInfo.InstallerType = WindowsInstallerTypeNullsoft
	} else if spellHas(spell, "\\b, self-extracting archive") {
		result.WindowsInfo.InstallerType = WindowsInstallerTypeArchive
	}

	if spellHas(spell, "\\b (GUI)") {
		result.WindowsInfo.Gui = true
	}

	if spellHas(spell, "Mono/.Net assembly") {
		result.WindowsInfo.DotNet = true
	}

	return result, nil
}

// peHeaderOffset returns the offset of the "PE\0\0" signature, or -1 when
// the file is not a PE image (a plain DOS executable, for instance).
func peHeaderOffset(head []byte, size int64) int64 {
	if len(head) < 0x40 || head[0] != 'M' || head[1] != 'Z' {
		return -1
	}
	off := int64(binary.LittleEndian.Uint32(head[0x3c:0x40]))
	if off == 0 || off+24 > size {
		return -1
	}
	return off
}

func peMachineArch(r *probeReader) Arch {
	off := peHeaderOffset(r.readHead(0x40), r.size)
	if off < 0 {
		return ""
	}
	hdr := r.readAt(off, 6)
	if hdr == nil || string(hdr[:4]) != "PE\x00\x00" {
		return ""
	}
	switch binary.LittleEndian.Uint16(hdr[4:6]) {
	case peMachineI386:
		return Arch386
	case peMachineAmd64:
		return ArchAmd64
	case peMachineArm64:
		return ArchArm64
	}
	return ""
}
