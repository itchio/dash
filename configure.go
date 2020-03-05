package dash

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/itchio/headway/state"
	"github.com/itchio/lake"
	"github.com/itchio/lake/pools"
	"github.com/itchio/lake/tlc"
	"github.com/itchio/pelican"
	"github.com/pkg/errors"
)

func sniffPoolEntry(pool lake.Pool, fileIndex int64, file *tlc.File) (*Candidate, error) {
	r, err := pool.GetReadSeeker(fileIndex)
	if err != nil {
		return nil, errors.Wrap(err, "while getting read seeker for pool entry")
	}

	size := pool.GetSize(fileIndex)

	return Sniff(r, file.Path, size)
}

func Sniff(r io.ReadSeeker, name string, size int64) (*Candidate, error) {
	c, err := doSniff(r, name, size)
	if c != nil {
		c.Size = size
		if c.Path == "" {
			c.Path = name
		}
		c.Depth = pathDepth(c.Path)
	}
	return c, err
}

func doSniff(r io.ReadSeeker, path string, size int64) (*Candidate, error) {
	lowerPath := strings.ToLower(path)

	lowerBase := filepath.Base(lowerPath)
	dir := filepath.Dir(path)
	switch lowerBase {
	case "index.html":
		return &Candidate{
			Flavor: FlavorHTML,
			Path:   path,
		}, nil
	case "conf.lua":
		return sniffLove(r, size, dir)
	}

	if strings.HasSuffix(lowerPath, ".love") {
		return &Candidate{
			Flavor: FlavorLove,
			Path:   path,
		}, nil
	}

	// if it ends in .exe, it's probably an .exe
	if strings.HasSuffix(lowerPath, ".exe") {
		subRes, subErr := sniffPE(r, size)
		if subErr != nil {
			return nil, errors.Wrap(subErr, "sniffing PE file")
		}
		if subRes != nil {
			// it was an exe!
			return subRes, nil
		}
		// it wasn't an exe, carry on...
	}

	// if it ends in .bat or .cmd, it's a windows script
	if strings.HasSuffix(lowerPath, ".bat") || strings.HasSuffix(lowerPath, ".cmd") {
		return &Candidate{
			Flavor: FlavorScriptWindows,
		}, nil
	}

	buf := make([]byte, 8)
	n, _ := io.ReadFull(r, buf)
	if n < len(buf) {
		// too short to be an exec or unreadable
		return nil, nil
	}

	// intel Mach-O executables start with 0xCEFAEDFE or 0xCFFAEDFE
	// (old PowerPC Mach-O executables started with 0xFEEDFACE)
	if (buf[0] == 0xCE || buf[0] == 0xCF) && buf[1] == 0xFA && buf[2] == 0xED && buf[3] == 0xFE {
		return &Candidate{
			Flavor: FlavorNativeMacos,
		}, nil
	}

	// Mach-O universal binaries start with 0xCAFEBABE
	// it's Apple's 'fat binary' stuff that contains multiple architectures
	// unfortunately, compiled Java classes also start with that
	if buf[0] == 0xCA && buf[1] == 0xFE && buf[2] == 0xBA && buf[3] == 0xBE {
		return sniffFatMach(r, size)
	}

	// ELF executables start with 0x7F454C46
	// (e.g. 0x7F + 'ELF' in ASCII)
	if buf[0] == 0x7F && buf[1] == 0x45 && buf[2] == 0x4C && buf[3] == 0x46 {
		return sniffELF(r, path, size)
	}

	// Shell scripts start with a shebang (#!)
	// https://en.wikipedia.org/wiki/Shebang_(Unix)
	if buf[0] == 0x23 && buf[1] == 0x21 {
		return sniffScript(r, size)
	}

	// MSI (Microsoft Installer Packages) have a well-defined magic number.
	if buf[0] == 0xD0 && buf[1] == 0xCF &&
		buf[2] == 0x11 && buf[3] == 0xE0 &&
		buf[4] == 0xA1 && buf[5] == 0xB1 &&
		buf[6] == 0x1A && buf[7] == 0xE1 {
		return &Candidate{
			Flavor: FlavorMSI,
		}, nil
	}

	if buf[0] == 0x50 && buf[1] == 0x4B &&
		buf[2] == 0x03 && buf[3] == 0x04 {
		return sniffZip(r, size)
	}

	return nil, nil
}

// ConfigureParams controls the behavior of Configure
type ConfigureParams struct {
	Consumer *state.Consumer
	// filter to use when walking the install folder a nil value will fallback
	// on lake's presets (not git/hg/svn metadata, no windows/mac metadata, no
	// .itch folder)
	Filter tlc.FilterFunc
	Stats  *VerdictStats
}

// Configure walks a directory and finds potential launch candidates,
// grouped together into a verdict.
func Configure(root string, params ConfigureParams) (*Verdict, error) {
	consumer := params.Consumer

	if params.Stats != nil {
		params.Stats.SniffsByExt = make(map[string]int)
	}

	filter := params.Filter
	if filter == nil {
		filter = tlc.PresetFilter
	}

	verdict := &Verdict{
		BasePath: root,
	}

	var pool lake.Pool

	container, err := tlc.WalkAny(root, tlc.WalkOpts{Filter: filter})
	if err != nil {
		return nil, err
	}

	pool, err = pools.New(container, root)
	if err != nil {
		return nil, errors.Wrap(err, "creating pool to configure folder")
	}

	defer pool.Close()

	var candidates = make([]*Candidate, 0)

	for _, d := range container.Dirs {
		lowerPath := strings.ToLower(d.Path)
		if strings.HasSuffix(lowerPath, ".app") {
			plistPath := lowerPath + "/contents/info.plist"

			plistFound := false
			for _, f := range container.Files {
				if strings.ToLower(f.Path) == plistPath {
					plistFound = true
					break
				}
			}

			if !plistFound {
				consumer.Logf("Found app bundle without an Info.plist: %s", d.Path)
				continue
			}

			res := &Candidate{
				Flavor: FlavorAppMacos,
				Size:   0,
				Path:   d.Path,
				Mode:   d.Mode,
			}
			res.Depth = pathDepth(res.Path)
			candidates = append(candidates, res)
		}
	}

	for fileIndex, f := range container.Files {
		verdict.TotalSize += f.Size
		if !isBlacklistedExt(f.Path) {
			if params.Stats != nil {
				params.Stats.NumSniffs++
				ext := getExt(f.Path)
				params.Stats.SniffsByExt[ext] = params.Stats.SniffsByExt[ext] + 1
			}

			res, err := sniffPoolEntry(pool, int64(fileIndex), f)
			if err != nil {
				return nil, errors.Wrap(err, "sniffing pool entry")
			}

			if res != nil {
				res.Mode = f.Mode
				candidates = append(candidates, res)
			}
		}
	}

	if len(candidates) == 0 && container.IsSingleFile() {
		f := container.Files[0]

		if hasExt(f.Path, ".html") {
			// ok, that's an HTML5 game
			candidate := &Candidate{
				Size:   f.Size,
				Path:   f.Path,
				Mode:   f.Mode,
				Depth:  pathDepth(f.Path),
				Flavor: FlavorHTML,
			}
			candidates = append(candidates, candidate)
		}
	}

	if len(candidates) == 0 {
		// still no candidates? if we have a top-level .html file, let's go for it
		for _, f := range container.Files {
			if pathDepth(f.Path) == 1 && hasExt(f.Path, ".html") {
				// ok, that's an HTML5 game
				candidate := &Candidate{
					Size:   f.Size,
					Path:   f.Path,
					Mode:   f.Mode,
					Depth:  pathDepth(f.Path),
					Flavor: FlavorHTML,
				}
				candidates = append(candidates, candidate)
			}
		}
	}

	verdict.Candidates = candidates

	return verdict, nil
}

type FixPermissionsParams struct {
	DryRun   bool
	Consumer *state.Consumer
}

// FixPermissions makes sure all ELF executables, COFF executables,
// and scripts have the executable bit set
func FixPermissions(v *Verdict, params FixPermissionsParams) ([]string, error) {
	consumer := params.Consumer

	var fixed []string

	for _, c := range v.Candidates {
		switch c.Flavor {
		case FlavorNativeLinux, FlavorNativeMacos, FlavorScript:
			fullPath := filepath.Join(v.BasePath, c.Path)

			if c.Mode&0100 == 0 {
				consumer.Debugf("Adding missing executable bit for (%s)/(%s)", filepath.Base(v.BasePath), c.Path)

				fixed = append(fixed, c.Path)
				if !params.DryRun {
					err := os.Chmod(fullPath, 0755)
					if err != nil {
						return nil, err
					}
				}
			}
		}

		c.Mode = 0
	}

	return fixed, nil
}

type biggestFirst struct {
	candidates []*Candidate
}

var _ sort.Interface = (*biggestFirst)(nil)

func (bf *biggestFirst) Len() int {
	return len(bf.candidates)
}

func (bf *biggestFirst) Less(i, j int) bool {
	return bf.candidates[i].Size > bf.candidates[j].Size
}

func (bf *biggestFirst) Swap(i, j int) {
	bf.candidates[i], bf.candidates[j] = bf.candidates[j], bf.candidates[i]
}

type HighestScoreFirst struct {
	candidates []ScoredCandidate
}

var _ sort.Interface = (*HighestScoreFirst)(nil)

func (hsf *HighestScoreFirst) Len() int {
	return len(hsf.candidates)
}

func (hsf *HighestScoreFirst) Less(i, j int) bool {
	return hsf.candidates[i].score > hsf.candidates[j].score
}

func (hsf *HighestScoreFirst) Swap(i, j int) {
	hsf.candidates[i], hsf.candidates[j] = hsf.candidates[j], hsf.candidates[i]
}

type BlacklistEntry struct {
	pattern *regexp.Regexp
	penalty Penalty
}

type PenaltyKind int

const (
	PenaltyExclude = iota
	PenaltyScore
)

type Penalty struct {
	kind  PenaltyKind
	delta int64
}

var blacklist = []BlacklistEntry{
	// Penalties
	{regexp.MustCompile(`(?i)unins.*\.exe$`), Penalty{PenaltyScore, 50}},
	{regexp.MustCompile(`(?i)kick\.bin$`), Penalty{PenaltyScore, 50}},
	{regexp.MustCompile(`(?i)\.vshost\.exe$`), Penalty{PenaltyScore, 50}},
	{regexp.MustCompile(`(?i)nacl_helper`), Penalty{PenaltyScore, 20}},
	{regexp.MustCompile(`(?i)nwjc\.exe$`), Penalty{PenaltyScore, 20}},
	{regexp.MustCompile(`(?i)flixel\.exe$`), Penalty{PenaltyScore, 20}},

	// Excludes
	{regexp.MustCompile(`(?i)\.(so|dylib)$`), Penalty{PenaltyExclude, 0}},
	{regexp.MustCompile(`(?i)dxwebsetup\.exe$`), Penalty{PenaltyExclude, 0}},
	{regexp.MustCompile(`(?i)vcredist.*\.exe$`), Penalty{PenaltyExclude, 0}},
	{regexp.MustCompile(`(?i)unitycrashhandler.*\.exe$`), Penalty{PenaltyExclude, 0}},
}

type ScoredCandidate struct {
	candidate *Candidate
	score     int64
}

type FilterParams struct {
	OS   string
	Arch string
}

// Filter candidates by OS and/or Arch
// OS and Arch may be empty strings.
//
// Returns a copy of this Verdict.
func (v Verdict) Filter(consumer *state.Consumer, params FilterParams) Verdict {
	osFilter := params.OS
	archFilter := params.Arch

	hasOS := func(os string) bool {
		return osFilter != "" && osFilter == os
	}
	excludesOS := func(os string) bool {
		return osFilter != "" && osFilter != os
	}
	hasArch := func(arch string) bool {
		return archFilter != "" && archFilter == arch
	}

	consumer.Debugf("Filtering %d candidates to os (%s), arch (%s)", len(v.Candidates), osFilter, archFilter)

	var compatibleCandidates []*Candidate

	// exclude things we can't run at all
	for _, c := range v.Candidates {
		keep := true

		consumer.Debugf("Reviewing (%s) flavor %v", c.Path, c.Flavor)
		switch c.Flavor {
		case FlavorNativeLinux:
			if excludesOS("linux") {
				consumer.Debugf("Excluding (%s) - linux native, os filter is (%s)", c.Path, osFilter)
				keep = false
			}

			if hasArch("386") && (c.Arch != "" && c.Arch != Arch386) {
				consumer.Debugf("Excluding (%s) - not 32-bit, but arch filter is (%s)", c.Path, archFilter)
				keep = false
			}
		case FlavorNativeWindows:
			if excludesOS("windows") {
				consumer.Debugf("Excluding (%s) - windows native, os filter is (%s)", c.Path, osFilter)
				keep = false
			}
		case FlavorNativeMacos, FlavorAppMacos:
			if excludesOS("darwin") {
				consumer.Debugf("Excluding (%s) - darwin (macOS) native, os filter is (%s)", c.Path, osFilter)
				keep = false
			}
		}

		if keep {
			compatibleCandidates = append(compatibleCandidates, c)
		}
	}
	bestCandidates := compatibleCandidates

	if len(bestCandidates) == 1 {
		v.Candidates = bestCandidates
		return v
	}

	// now keep all candidates of the lowest depth
	lowestDepth := 4096
	for _, c := range v.Candidates {
		if c.Depth < lowestDepth {
			lowestDepth = c.Depth
		}
	}

	bestCandidates = selectByFunc(compatibleCandidates, func(c *Candidate) bool {
		pass := c.Depth == lowestDepth
		if !pass {
			consumer.Debugf("Excluding (%s) - depth %d > lowest depth %d", c.Path, c.Depth, lowestDepth)
		}
		return pass
	})

	if len(bestCandidates) == 1 {
		v.Candidates = bestCandidates
		return v
	}

	// love always wins, in the end
	{
		loveCandidates := selectByFlavor(bestCandidates, FlavorLove)

		if len(loveCandidates) == 1 {
			consumer.Debugf("Found single .love candidate")
			v.Candidates = loveCandidates
			return v
		}
	}

	// on macOS, app bundles win
	if hasOS("darwin") {
		appCandidates := selectByFlavor(bestCandidates, FlavorAppMacos)

		if len(appCandidates) > 0 {
			consumer.Debugf("Found some .app bundles")
			bestCandidates = appCandidates
		}
	}

	// on windows, scripts win
	if hasOS("windows") {
		scriptCandidates := selectByFlavor(bestCandidates, FlavorScriptWindows)

		if len(scriptCandidates) == 1 {
			consumer.Debugf("Found single windows script (%s)", scriptCandidates[0].Path)
			v.Candidates = scriptCandidates
			return v
		}
	}

	// on linux, scripts win
	if hasOS("linux") {
		scriptCandidates := selectByFlavor(bestCandidates, FlavorScript)

		if len(scriptCandidates) == 1 {
			consumer.Debugf("Found single Linux script (%s)", scriptCandidates[0].Path)
			v.Candidates = scriptCandidates
			return v
		}
	}

	if hasOS("linux") && hasArch("amd64") {
		consumer.Debugf("Oh boy, we're on 64-bit Linux, let's filter some stuff")

		linuxCandidates := selectByFlavor(bestCandidates, FlavorNativeLinux)
		linux64Candidates := selectByArch(linuxCandidates, ArchAmd64)

		if len(linux64Candidates) > 0 {
			consumer.Debugf("Found some native 64-bit Linux candidates, excluding all others")

			// on linux 64, 64-bit binaries win
			bestCandidates = linux64Candidates
		} else {
			consumer.Debugf("No native 64-bit Linux candidates, looking for jars")

			// if no 64-bit binaries, jars win
			jarCandidates := selectByFlavor(bestCandidates, FlavorJar)
			if len(jarCandidates) > 0 {
				consumer.Debugf("Found some jar candidates, excluding all others")

				v.Candidates = jarCandidates
				return v
			}
		}
	}

	// on windows, non-installers win
	if hasOS("windows") {
		windowsCandidates := selectByFlavor(bestCandidates, FlavorNativeWindows)
		nonInstallerCandidates := selectByFunc(windowsCandidates, func(c *Candidate) bool {
			if c.WindowsInfo != nil && c.WindowsInfo.InstallerType != "" {
				consumer.Debugf("Excluding (%s) - installer of type (%s)", c.Path, c.WindowsInfo.InstallerType)
				return false // false means "is an installer"
			}

			fullTargetPath := filepath.FromSlash(c.Path)
			f, err := os.Open(filepath.Join(v.BasePath, fullTargetPath))
			if err != nil {
				consumer.Warnf("Could not open native windows candidate (%s) for inspection", fullTargetPath)
				consumer.Warnf("Full error: %#v", err)
			} else {
				defer f.Close()

				var peLines []string
				memConsumer := &state.Consumer{
					OnMessage: func(lvl string, msg string) {
						peLines = append(peLines, fmt.Sprintf("pelican> [%s] %s", lvl, msg))
					},
				}

				peInfo, err := pelican.Probe(f, &pelican.ProbeParams{
					Consumer: memConsumer,
				})
				if err != nil {
					consumer.Warnf("Could not probe (%s) with pelican", fullTargetPath)
					consumer.Warnf("Full error: %#v", err)
					consumer.Warnf("Full pelican log:\n%s", strings.Join(peLines, "\n"))
				} else {
					if peInfo.RequiresElevation() {
						consumer.Debugf("Excluding (%s) - requires elevation", c.Path)
						return false // false means "is an installer"
					}

					if peInfo.AssemblyInfo == nil && HasSuspiciouslySetupLikeName(filepath.Base(c.Path)) {
						consumer.Debugf("Excluding (%s) - no assembly info + has suspiciously setup-like name", c.Path)
						return false // false means "is an installer"
					}
				}
			}

			return true // can't tell if installer or not
		})

		bestCandidates = nonInstallerCandidates

		if len(bestCandidates) == 1 {
			v.Candidates = bestCandidates
			return v
		}
	}

	// on windows, gui executables win
	if hasOS("windows") {
		windowsCandidates := selectByFlavor(bestCandidates, FlavorNativeWindows)
		guiCandidates := selectByFunc(windowsCandidates, func(c *Candidate) bool {
			pass := c.WindowsInfo != nil && c.WindowsInfo.Gui
			if !pass {
				consumer.Debugf("Considering (%s) for exclusion - not a GUI executable", c.Path)
			}
			return pass
		})

		if len(guiCandidates) > 0 {
			bestCandidates = guiCandidates
		}

		if len(bestCandidates) == 1 {
			v.Candidates = bestCandidates
			return v
		}
	}

	// everywhere, HTMLs lose if there's anything else good
	{
		htmlCandidates := selectByFlavor(bestCandidates, FlavorHTML)
		if len(htmlCandidates) > 0 && len(htmlCandidates) < len(bestCandidates) {
			consumer.Debugf("Has %d HTML candidates, but %d non-HTML candidates - excluding HTML candidates", len(htmlCandidates), len(bestCandidates)-len(htmlCandidates))
			bestCandidates = selectByFunc(bestCandidates, func(c *Candidate) bool {
				return c.Flavor != FlavorHTML
			})
		}
	}

	// everywhere, jars lose if there's anything else good
	{
		jarCandidates := selectByFlavor(bestCandidates, FlavorJar)
		if len(jarCandidates) > 0 && len(jarCandidates) < len(bestCandidates) {
			consumer.Debugf("Has %d JAR candidates, but %d non-JAR candidates - excluding JAR candidates", len(jarCandidates), len(bestCandidates)-len(jarCandidates))
			bestCandidates = selectByFunc(bestCandidates, func(c *Candidate) bool {
				return c.Flavor != FlavorJar
			})
		}
	}

	sort.Stable(&biggestFirst{bestCandidates})

	// score, filter & sort
	computeScore := func(candidate *Candidate) ScoredCandidate {
		var score int64 = 100
		for _, entry := range blacklist {
			if entry.pattern.MatchString(candidate.Path) {
				switch entry.penalty.kind {
				case PenaltyScore:
					consumer.Debugf("Penalizing (%s) - %d score penalty for pattern %q", candidate.Path, entry.penalty.delta, entry.pattern)
					score -= entry.penalty.delta
				case PenaltyExclude:
					consumer.Debugf("0-scoring (%s) - penalty exclude for pattern %q", candidate.Path, entry.pattern)
					score = 0
				}
			}
		}

		return ScoredCandidate{candidate, score}
	}

	var scoredCandidates []ScoredCandidate
	for _, candidate := range bestCandidates {
		scored := computeScore(candidate)
		if scored.score > 0 {
			scoredCandidates = append(scoredCandidates, scored)
		} else {
			consumer.Debugf("Excluding (%s) - non-positive score %d", candidate.Path, scored.score)
		}
	}
	sort.Stable(&HighestScoreFirst{scoredCandidates})
	consumer.Debugf("Sorted candidates: ")
	for _, sc := range scoredCandidates {
		consumer.Debugf("- [%d] (%s)", sc.score, sc.candidate.Path)
	}

	var finalCandidates []*Candidate
	for _, scored := range scoredCandidates {
		finalCandidates = append(finalCandidates, scored.candidate)
	}

	v.Candidates = finalCandidates
	return v
}
