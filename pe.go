package dash

import (
	"io"
	"strings"

	"github.com/itchio/pelican"
	"github.com/itchio/pelican/pe"
	"github.com/itchio/spellbook"
	"github.com/itchio/wizardry/wizardry/wizutil"
)

func sniffPE(r *probeReader, size int64) (*Candidate, error) {
	var arch Arch
	var installer installerSniff
	{
		pr := newProbeReader(r.rs, size, newProbeBudget(peProbeBytes))
		// both readers move the same underlying file
		defer r.Seek(r.pos, io.SeekStart)
		if f, err := pe.NewFile(pr, size); err == nil {
			arch = Arch(pelican.MachineArch(f.Machine))
			installer = sniffWindowsInstaller(f)
		}
	}

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

	result.Arch = arch
	if result.Arch == "" {
		if spellHas(spell, "\\b32 executable") {
			result.Arch = Arch386
		} else if spellHas(spell, "\\b32+ executable") {
			result.Arch = ArchAmd64
		}
	}
	result.WindowsInfo.Arch = result.Arch

	result.WindowsInfo.InstallerType = installer.installerType
	result.setEngine(installer.engine)
	if result.WindowsInfo.InstallerType == "" {
		if spellHas(spell, "\\b, InnoSetup uninstaller") {
			result.WindowsInfo.InstallerType = WindowsInstallerTypeInno
			result.WindowsInfo.Uninstaller = true
		} else {
			result.WindowsInfo.InstallerType = spellInstallerType(spell)
		}
	}

	if spellHas(spell, "\\b (GUI)") {
		result.WindowsInfo.Gui = true
	}

	if spellHas(spell, "Mono/.Net assembly") {
		result.WindowsInfo.DotNet = true
	}

	return result, nil
}

// spellInstallerType maps spellbook's verdicts. Its rules assume fixed
// header layouts, so they only fill in what sniffWindowsInstaller missed.
func spellInstallerType(spell []string) WindowsInstallerType {
	switch {
	case spellHas(spell, "\\b, InnoSetup installer"):
		return WindowsInstallerTypeInno
	case spellHas(spell, "\\b, Nullsoft Installer self-extracting archive"):
		return WindowsInstallerTypeNullsoft
	case spellHas(spell, "\\b, RAR self-extracting archive"):
		return WindowsInstallerTypeWinRAR
	}
	// InstallShield, WISE, WinZip, ARJ, LHa and the rest: known to be
	// packages, not known to be extractable
	for _, token := range spell {
		if strings.Contains(token, "self-extracting archive") {
			return WindowsInstallerTypeArchive
		}
	}
	return ""
}
