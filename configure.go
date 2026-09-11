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

// Sniff identifies a single file by name and magic. It is what the magic
// pass of Configure runs per file; engine detection needs the whole folder
// and only happens in Configure.
func Sniff(r io.ReadSeeker, name string, size int64) (*Candidate, error) {
	return sniff(newProbeReader(r, size, newProbeBudget(0)), name, size)
}

func sniff(r *probeReader, name string, size int64) (*Candidate, error) {
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

func doSniff(r *probeReader, path string, size int64) (*Candidate, error) {
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
		return sniffLoveConf(r, dir)
	}

	if strings.HasSuffix(lowerPath, ".love") {
		return sniffLoveArchive(r, path, size)
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

	buf := r.readHead(8)
	if len(buf) < 8 {
		// too short to be an exec or unreadable
		return nil, nil
	}

	// intel Mach-O executables start with 0xCEFAEDFE or 0xCFFAEDFE
	// (old PowerPC Mach-O executables started with 0xFEEDFACE)
	if (buf[0] == 0xCE || buf[0] == 0xCF) && buf[1] == 0xFA && buf[2] == 0xED && buf[3] == 0xFE {
		return sniffMachO(r, size)
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

	// MaxProbeBytes caps how many distinct bytes of any single file
	// sniffing and engine detection together may read. Zero means
	// DefaultMaxProbeBytes. The magic matchers read a 128 KiB window at a
	// time, so values below that stop executables from being recognized
	// at all.
	MaxProbeBytes int64

	// DeepProbe fills the dependency record of native candidates
	// (LinuxInfo.Imports, GlibcVersion, WindowsInfo.Imports). It parses
	// section and symbol tables and is not subject to MaxProbeBytes, so
	// leave it off at launch time.
	DeepProbe bool
}

// detectors run in this order, after the magic pass. Order only matters
// where one detector reads what another annotated, and none do today.
var detectors = []engineDetector{
	loveDetector{},
	godotDetector{},
	gamemakerDetector{},
	pico8Detector{},
	romDetector{},
	dosDetector{},
	wadDetector{},
	renpyDetector{},
	rpgmakerDetector{},
	agsDetector{},
	swfDetector{},
	pyxelDetector{},
	solarusDetector{},
	tic80Detector{},
	openborDetector{},
	unityDetector{},
	unrealDetector{},
	dotnetDetector{},
	hashlinkDetector{},
	defoldDetector{},
	constructDetector{},
	shellDetector{},
	pythonDetector{},
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

	s := newScan(params, pool, container)
	s.candidates = make([]*Candidate, 0)

	// lowercased path of each .app bundle's main executable, when its
	// Info.plist declares one
	bundleExecutables := make(map[*Candidate]string)

	for _, d := range container.Dirs {
		lowerPath := strings.ToLower(d.Path)
		if strings.HasSuffix(lowerPath, ".app") {
			plistPath := lowerPath + "/contents/info.plist"

			plistIndex, ok := s.file(plistPath)
			if !ok {
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
			s.candidates = append(s.candidates, res)

			exe, err := readBundleExecutable(pool, int64(plistIndex))
			if err != nil {
				consumer.Logf("Could not read Info.plist of %s: %s", d.Path, err.Error())
			} else if exe != "" {
				bundleExecutables[res] = lowerPath + "/contents/macos/" + strings.ToLower(exe)
			}
		}
	}

	for fileIndex, f := range container.Files {
		verdict.TotalSize += f.Size
		if isBlacklistedExt(f.Path) {
			continue
		}
		if params.Stats != nil {
			params.Stats.NumSniffs++
			ext := getExt(f.Path)
			params.Stats.SniffsByExt[ext] = params.Stats.SniffsByExt[ext] + 1
		}

		r, err := s.open(fileIndex)
		if err != nil {
			return nil, errors.Wrap(err, "sniffing pool entry")
		}
		res, err := sniff(r, f.Path, r.size)
		if err != nil {
			return nil, errors.Wrap(err, "sniffing pool entry")
		}

		if res != nil {
			res.Mode = f.Mode
			s.candidates = append(s.candidates, res)
		}
	}

	if len(s.candidates) == 0 && container.IsSingleFile() {
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
			s.candidates = append(s.candidates, candidate)
		}
	}

	if len(s.candidates) == 0 {
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
				s.candidates = append(s.candidates, candidate)
			}
		}
	}

	// .app bundles inherit the architecture of their main executable. Without
	// a CFBundleExecutable to go by, fall back to the first Mach-O found in
	// Contents/MacOS/, which may be a helper rather than the real entry point.
	for _, appCandidate := range s.candidates {
		if appCandidate.Flavor != FlavorAppMacos {
			continue
		}
		macosPrefix := strings.ToLower(appCandidate.Path) + "/contents/macos/"
		declared := bundleExecutables[appCandidate]

		var match *Candidate
		for _, c := range s.candidates {
			if c.Flavor != FlavorNativeMacos {
				continue
			}
			cPath := strings.ToLower(c.Path)
			if cPath == declared {
				match = c
				break
			}
			if match == nil && declared == "" && strings.HasPrefix(cPath, macosPrefix) {
				match = c
			}
		}
		if match != nil {
			appCandidate.Arch = match.Arch
			appCandidate.MacosInfo = match.MacosInfo
		}
	}

	for _, d := range detectors {
		if err := d.detect(s); err != nil {
			return nil, errors.Wrapf(err, "engine detector %T", d)
		}
	}

	if params.DeepProbe {
		s.deepProbe()
	}

	verdict.Candidates = s.candidates

	return verdict, nil
}

// probePE runs pelican on an executable, turning a panic on a malformed
// image into an error: uploads are not trusted input.
func probePE(f *eosFile, consumer *state.Consumer) (info *pelican.PeInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			info = nil
			err = fmt.Errorf("pelican panicked: %v", r)
		}
	}()
	return pelican.Probe(f, pelican.ProbeParams{Consumer: consumer})
}

// deepProbe fills the native dependency records. Failures are logged, not
// fatal: a candidate without a record is still a candidate.
func (s *scan) deepProbe() {
	for _, c := range s.candidates {
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		switch c.Flavor {
		case FlavorNativeLinux:
			r, _, err := s.openRaw(index)
			if err != nil {
				s.logf("deep probe: %s", err)
				continue
			}
			if c.LinuxInfo == nil {
				c.LinuxInfo = &LinuxInfo{Arch: c.Arch}
			}
			if err := probeELF(&readerAtFromSeeker{r}, c.LinuxInfo); err != nil {
				s.logf("deep probe: %s: %s", c.Path, err)
			}
		case FlavorNativeWindows:
			r, size, err := s.openRaw(index)
			if err != nil {
				s.logf("deep probe: %s", err)
				continue
			}
			if c.WindowsInfo == nil {
				c.WindowsInfo = &WindowsInfo{}
			}
			var peLines []string
			memConsumer := &state.Consumer{
				OnMessage: func(lvl string, msg string) {
					peLines = append(peLines, fmt.Sprintf("pelican> [%s] %s", lvl, msg))
				},
			}
			info, err := probePE(&eosFile{rs: r, ra: &readerAtFromSeeker{r}, size: size, name: c.Path}, memConsumer)
			if err != nil {
				s.logf("deep probe: %s: %s\n%s", c.Path, err, strings.Join(peLines, "\n"))
				continue
			}
			c.WindowsInfo.Imports = info.Imports
			if c.WindowsInfo.Arch == "" {
				c.WindowsInfo.Arch = Arch(info.Arch)
			}
			if len(info.VersionProperties) > 0 {
				c.WindowsInfo.VersionProperties = info.VersionProperties
			}
			if info.AssemblyInfo != nil {
				c.WindowsInfo.RequestedExecutionLevel = info.AssemblyInfo.RequestedExecutionLevel
			}
		}
	}
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
	{regexp.MustCompile(`(?i)chrome-sandbox$`), Penalty{PenaltyScore, 20}},
	{regexp.MustCompile(`(?i)crashpad_handler`), Penalty{PenaltyScore, 20}},
	{regexp.MustCompile(`(?i)notification_helper\.exe$`), Penalty{PenaltyScore, 20}},

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
	// Runtimes lists the payload flavors the host can run with a runtime of
	// its own: "godot-pck", "love", "rom:snes" (or "rom" for every system).
	// Matching candidates survive alongside natives instead of losing to
	// them, and are ranked with them by size and score.
	Runtimes []Flavor
}

// supportsRuntime reports whether a payload candidate is covered by the
// host's runtime list.
func (params FilterParams) supportsRuntime(c *Candidate) bool {
	if !c.IsPayload() {
		return false
	}
	for _, r := range params.Runtimes {
		if r == c.Flavor {
			return true
		}
		if c.Flavor == FlavorROM && c.Engine != nil && r == Flavor("rom:"+romSystem(c)) {
			return true
		}
	}
	return false
}

func romSystem(c *Candidate) string {
	if c.Engine == nil {
		return ""
	}
	system, _ := c.Engine.Details["system"].(string)
	return system
}

// Filter candidates by OS and/or Arch
// OS and Arch may be empty strings.
//
// Returns a copy of this Verdict.
func (v Verdict) Filter(consumer *state.Consumer, params FilterParams) Verdict {
	if len(params.Runtimes) == 0 {
		return v.filterHost(consumer, params)
	}

	// payloads the host has a runtime for skip the host rules entirely and
	// rejoin the natives for the final ranking
	var runtimeCandidates []*Candidate
	hostVerdict := v
	hostVerdict.Candidates = nil
	for _, c := range v.Candidates {
		if params.supportsRuntime(c) {
			consumer.Debugf("Keeping (%s) - host has a runtime for flavor %v", c.Path, c.Flavor)
			runtimeCandidates = append(runtimeCandidates, c)
		} else {
			hostVerdict.Candidates = append(hostVerdict.Candidates, c)
		}
	}
	if len(runtimeCandidates) == 0 {
		return v.filterHost(consumer, params)
	}

	// a host that named its runtimes and found a match has no use for the
	// engine payloads it did not name
	hostVerdict.Candidates = selectByFunc(hostVerdict.Candidates, func(c *Candidate) bool {
		if enginePayloadFlavors[c.Flavor] {
			consumer.Debugf("Excluding (%s) - flavor %v has no runtime on this host", c.Path, c.Flavor)
			return false
		}
		return true
	})

	best := hostVerdict.filterHost(consumer, params).Candidates
	best = append(best, runtimeCandidates...)
	v.Candidates = rankCandidates(consumer, best)
	return v
}

func (v Verdict) filterHost(consumer *state.Consumer, params FilterParams) Verdict {
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

			// Intel Macs have no way to run arm64-only binaries
			if hasArch("amd64") && c.Arch == ArchArm64 {
				consumer.Debugf("Excluding (%s) - arm64-only, but arch filter is (%s)", c.Path, archFilter)
				keep = false
			}
		case FlavorScript:
			// shebang scripts run on linux and macOS, but not windows
			if hasOS("windows") {
				consumer.Debugf("Excluding (%s) - shebang script, os filter is (%s)", c.Path, osFilter)
				keep = false
			}
		}

		if keep {
			compatibleCandidates = append(compatibleCandidates, c)
		}
	}
	// a payload that shares its path with an executable (a fused LÖVE exe,
	// an embedded Godot pck) is that executable seen through a runtime's
	// eyes. Hosts without runtimes launch the executable, and hosts with
	// runtimes never reach this point with it, so it must not compete here
	// or the love rule would hand butler an exe to run with love
	nativePaths := make(map[string]bool)
	for _, c := range v.Candidates {
		if c.IsNative() {
			nativePaths[c.Path] = true
		}
	}
	compatibleCandidates = selectByFunc(compatibleCandidates, func(c *Candidate) bool {
		if c.IsPayload() && nativePaths[c.Path] {
			consumer.Debugf("Excluding (%s) - %v payload embedded in an executable", c.Path, c.Flavor)
			return false
		}
		return true
	})

	// engine payloads the host has no runtime for are data files: they lose
	// to anything else right away, before the depth cutoff or the html rule
	// could let a project folder shadow the launcher inside it
	{
		payloadCandidates := selectByFunc(compatibleCandidates, func(c *Candidate) bool {
			return enginePayloadFlavors[c.Flavor]
		})
		if len(payloadCandidates) > 0 && len(payloadCandidates) < len(compatibleCandidates) {
			consumer.Debugf("Has %d engine payload candidates, but %d others - excluding payloads", len(payloadCandidates), len(compatibleCandidates)-len(payloadCandidates))
			compatibleCandidates = selectByFunc(compatibleCandidates, func(c *Candidate) bool {
				return !enginePayloadFlavors[c.Flavor]
			})
		}
	}

	bestCandidates := compatibleCandidates

	if len(bestCandidates) == 1 {
		v.Candidates = bestCandidates
		return v
	}

	// now keep all candidates of the lowest depth
	lowestDepth := 4096
	for _, c := range compatibleCandidates {
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

				peInfo, err := pelican.Probe(f, pelican.ProbeParams{
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

		if len(nonInstallerCandidates) > 0 {
			// non-installer native executables beat everything else
			bestCandidates = nonInstallerCandidates
		} else if len(windowsCandidates) > 0 && len(windowsCandidates) < len(bestCandidates) {
			// every native executable is an installer: installers lose
			// to the remaining candidates
			consumer.Debugf("All %d native windows candidates are installers, excluding them", len(windowsCandidates))
			bestCandidates = selectByFunc(bestCandidates, func(c *Candidate) bool {
				return c.Flavor != FlavorNativeWindows
			})
		}

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

	// on Apple Silicon, native builds beat Intel-only builds that would need
	// Rosetta, which Apple is phasing out after macOS 27
	if hasOS("darwin") && hasArch("arm64") {
		isMacos := func(c *Candidate) bool {
			return c.Flavor == FlavorNativeMacos || c.Flavor == FlavorAppMacos
		}
		nativeCandidates := selectByFunc(bestCandidates, func(c *Candidate) bool {
			return isMacos(c) && c.HasMacosArch(ArchArm64)
		})
		if len(nativeCandidates) > 0 {
			bestCandidates = selectByFunc(bestCandidates, func(c *Candidate) bool {
				if isMacos(c) && c.Arch != "" && !c.HasMacosArch(ArchArm64) {
					consumer.Debugf("Excluding (%s) - Intel-only, native arm64 candidates exist", c.Path)
					return false
				}
				return true
			})
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

	v.Candidates = rankCandidates(consumer, bestCandidates)
	return v
}

// rankCandidates orders by size, then applies name penalties and orders by
// score, dropping excluded names.
func rankCandidates(consumer *state.Consumer, candidates []*Candidate) []*Candidate {
	bestCandidates := append([]*Candidate(nil), candidates...)
	sort.Stable(&biggestFirst{bestCandidates})

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
	return finalCandidates
}
