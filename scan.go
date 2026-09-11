package dash

import (
	"io"
	"strings"

	"github.com/itchio/headway/state"
	"github.com/itchio/lake"
	"github.com/itchio/lake/tlc"
	"github.com/pkg/errors"
)

// engineDetector runs once after the magic pass, with the full listing and
// the candidates found so far. It may add payload candidates and annotate
// existing ones. Detectors are independent: two matching the same folder
// both emit, the consumer picks.
type engineDetector interface {
	detect(s *scan) error
}

// scan is the state shared by Configure and the engine detectors.
type scan struct {
	params    ConfigureParams
	consumer  *state.Consumer
	pool      lake.Pool
	container *tlc.Container

	// lowercased file paths, index-aligned with container.Files
	lowerFiles []string
	// lowercased path -> file index
	fileIndex map[string]int
	// lowercased dir paths ("" is the root), including every ancestor of a file
	dirs map[string]bool

	candidates []*Candidate

	// last tailWindow bytes of files the detectors looked at, so the five
	// trailer checks on every executable cost one open, not five
	tails map[int][]byte
	// per-file read budgets, shared by every open of the same file
	budgets map[int]*probeBudget
}

// tailWindow covers a zip end-of-central-directory record with the
// largest possible comment, which is also more than any other trailer
// the detectors look for.
const tailWindow = 65535 + 22

func newScan(params ConfigureParams, pool lake.Pool, container *tlc.Container) *scan {
	s := &scan{
		params:     params,
		consumer:   params.Consumer,
		pool:       pool,
		container:  container,
		lowerFiles: make([]string, len(container.Files)),
		fileIndex:  make(map[string]int, len(container.Files)),
		dirs:       map[string]bool{"": true},
	}
	for i, f := range container.Files {
		lp := strings.ToLower(f.Path)
		s.lowerFiles[i] = lp
		s.fileIndex[lp] = i
		for d := parentDir(lp); d != ""; d = parentDir(d) {
			if s.dirs[d] {
				break
			}
			s.dirs[d] = true
		}
	}
	for _, d := range container.Dirs {
		s.dirs[strings.ToLower(d.Path)] = true
	}
	return s
}

func (s *scan) logf(format string, args ...any) {
	if s.consumer != nil {
		s.consumer.Debugf(format, args...)
	}
}

// file looks up a file by exact (case-insensitive) path.
func (s *scan) file(lowerPath string) (int, bool) {
	i, ok := s.fileIndex[lowerPath]
	return i, ok
}

// hasFile is file without the index.
func (s *scan) hasFile(lowerPath string) bool {
	_, ok := s.fileIndex[lowerPath]
	return ok
}

func (s *scan) hasDir(lowerPath string) bool {
	return s.dirs[lowerPath]
}

// open returns a budgeted reader for a file. The pool caches one open
// reader, so callers must finish with it before opening another. The
// budget is per file, not per open: MaxProbeBytes caps the distinct bytes
// every sniffer and detector together may read from one file.
func (s *scan) open(index int) (*probeReader, error) {
	r, err := s.pool.GetReadSeeker(int64(index))
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", s.container.Files[index].Path)
	}
	budget, ok := s.budgets[index]
	if !ok {
		if s.budgets == nil {
			s.budgets = make(map[int]*probeBudget)
		}
		budget = newProbeBudget(s.params.MaxProbeBytes)
		s.budgets[index] = budget
	}
	return newProbeReader(r, s.pool.GetSize(int64(index)), budget), nil
}

// openRaw returns an unbudgeted reader, for the deep probe only.
func (s *scan) openRaw(index int) (io.ReadSeeker, int64, error) {
	r, err := s.pool.GetReadSeeker(int64(index))
	if err != nil {
		return nil, 0, errors.Wrapf(err, "opening %s", s.container.Files[index].Path)
	}
	return r, s.pool.GetSize(int64(index)), nil
}

// readHead returns the first n bytes of a file, or nil on any failure.
func (s *scan) readHead(index int, n int) []byte {
	r, err := s.open(index)
	if err != nil {
		return nil
	}
	return r.readHead(n)
}

// readTail returns the last n bytes of a file, or nil on any failure.
// Requests within tailWindow are served from a per-file cache.
func (s *scan) readTail(index int, n int) []byte {
	if n > tailWindow {
		r, err := s.open(index)
		if err != nil {
			return nil
		}
		return r.readTail(n)
	}
	tail, ok := s.tails[index]
	if !ok {
		r, err := s.open(index)
		if err != nil {
			return nil
		}
		tail = r.readTail(tailWindow)
		if tail == nil {
			// the window is over budget; the caller's smaller read may
			// still fit, and a later caller gets to try the window again
			return r.readTail(n)
		}
		if s.tails == nil {
			s.tails = make(map[int][]byte)
		}
		s.tails[index] = tail
	}
	// a cached tail shorter than the window is the whole file
	if len(tail) < n {
		n = len(tail)
	}
	if n == 0 {
		return nil
	}
	return tail[len(tail)-n:]
}

// filesWithSuffix returns the indices of files with the given lowercased suffix.
func (s *scan) filesWithSuffix(suffix string) []int {
	var res []int
	for i, lp := range s.lowerFiles {
		if strings.HasSuffix(lp, suffix) {
			res = append(res, i)
		}
	}
	return res
}

// filesNamed returns the indices of files with the given lowercased base name.
func (s *scan) filesNamed(name string) []int {
	var res []int
	for i, lp := range s.lowerFiles {
		if lowerBase(lp) == name {
			res = append(res, i)
		}
	}
	return res
}

// filesUnder returns the indices of files anywhere below a lowercased dir.
func (s *scan) filesUnder(lowerDir string) []int {
	prefix := lowerDir + "/"
	if lowerDir == "" {
		prefix = ""
	}
	var res []int
	for i, lp := range s.lowerFiles {
		if strings.HasPrefix(lp, prefix) {
			res = append(res, i)
		}
	}
	return res
}

// candidateAt returns the candidate for a path, if any.
func (s *scan) candidateAt(lowerPath string) *Candidate {
	for _, c := range s.candidates {
		if strings.ToLower(c.Path) == lowerPath {
			return c
		}
	}
	return nil
}

// nativesIn returns native candidates directly inside a lowercased dir.
func (s *scan) nativesIn(lowerDir string) []*Candidate {
	var res []*Candidate
	for _, c := range s.candidates {
		if !c.IsNative() {
			continue
		}
		if parentDir(strings.ToLower(c.Path)) == lowerDir {
			res = append(res, c)
		}
	}
	return res
}

// nativesUnder returns native candidates anywhere below a lowercased dir.
func (s *scan) nativesUnder(lowerDir string) []*Candidate {
	prefix := lowerDir + "/"
	if lowerDir == "" {
		prefix = ""
	}
	var res []*Candidate
	for _, c := range s.candidates {
		if c.IsNative() && strings.HasPrefix(strings.ToLower(c.Path), prefix) {
			res = append(res, c)
		}
	}
	return res
}

// annotateNativesIn sets the engine on every native directly inside a dir.
func (s *scan) annotateNativesIn(lowerDir string, info *EngineInfo) {
	for _, c := range s.nativesIn(lowerDir) {
		c.setEngine(cloneEngine(info))
	}
}

// annotateAround annotates the natives directly inside a dir, and when the
// dir sits inside a macOS bundle, the bundle and its Contents/MacOS natives:
// engines put their payload in Contents/Resources and the runner next door.
func (s *scan) annotateAround(lowerDir string, info *EngineInfo) {
	s.annotateNativesIn(lowerDir, info)
	if i := strings.Index(lowerDir, ".app/contents/"); i >= 0 {
		app := lowerDir[:i+4]
		if c := s.candidateAt(app); c != nil && c.Flavor == FlavorAppMacos {
			c.setEngine(cloneEngine(info))
		}
		s.annotateNativesIn(app+"/contents/macos", info)
	}
}

// addFileCandidate registers a candidate for a file entry.
func (s *scan) addFileCandidate(index int, flavor Flavor, info *EngineInfo) *Candidate {
	f := s.container.Files[index]
	c := &Candidate{
		Path:   f.Path,
		Mode:   f.Mode,
		Depth:  pathDepth(f.Path),
		Flavor: flavor,
		Size:   f.Size,
		Engine: info,
	}
	s.candidates = append(s.candidates, c)
	return c
}

// addDirCandidate registers a directory-shaped candidate. The root folder
// is "." and a directory's depth is that of the files directly inside it,
// so Filter's depth cutoff never lets a folder shadow the natives it holds.
func (s *scan) addDirCandidate(dir string, flavor Flavor, info *EngineInfo) *Candidate {
	path := dir
	depth := pathDepth(dir) + 1
	if dir == "" {
		path = "."
		depth = 1
	}
	c := &Candidate{
		Path:   path,
		Depth:  depth,
		Flavor: flavor,
		Engine: info,
	}
	s.candidates = append(s.candidates, c)
	return c
}

// originalDir returns a directory path with its original casing, given
// the lowercased form, by looking at any file inside it.
func (s *scan) originalDir(lowerDir string) string {
	if lowerDir == "" {
		return ""
	}
	for i, lp := range s.lowerFiles {
		if strings.HasPrefix(lp, lowerDir+"/") {
			return s.container.Files[i].Path[:len(lowerDir)]
		}
	}
	for _, d := range s.container.Dirs {
		if strings.ToLower(d.Path) == lowerDir {
			return d.Path
		}
	}
	return lowerDir
}

func cloneEngine(info *EngineInfo) *EngineInfo {
	if info == nil {
		return nil
	}
	c := &EngineInfo{Engine: info.Engine, Version: info.Version}
	for k, v := range info.Details {
		c.detail(k, v)
	}
	return c
}
