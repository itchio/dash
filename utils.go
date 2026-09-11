package dash

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func spellHas(spell []string, token string) bool {
	return slices.Contains(spell, token)
}

func pathDepth(path string) int {
	return len(strings.Split(path, "/"))
}

func hasExt(path string, ext string) bool {
	return strings.HasSuffix(strings.ToLower(path), ext)
}

func getExt(path string) string {
	return strings.ToLower(filepath.Ext(path))
}

// Adapt an io.ReadSeeker into an io.ReaderAt in the dumbest possible fashion

type readerAtFromSeeker struct {
	rs io.ReadSeeker
}

var _ io.ReaderAt = (*readerAtFromSeeker)(nil)

func (r *readerAtFromSeeker) ReadAt(b []byte, off int64) (int, error) {
	_, err := r.rs.Seek(off, io.SeekStart)
	if err != nil {
		return 0, err
	}

	return r.rs.Read(b)
}

func selectByFlavor(candidates []*Candidate, f Flavor) []*Candidate {
	res := make([]*Candidate, 0)
	for _, c := range candidates {
		if c.Flavor == f {
			res = append(res, c)
		}
	}
	return res
}

func selectByArch(candidates []*Candidate, a Arch) []*Candidate {
	res := make([]*Candidate, 0)
	for _, c := range candidates {
		if c.Arch == a {
			res = append(res, c)
		}
	}
	return res
}

type candidateFilter func(candidate *Candidate) bool

func selectByFunc(candidates []*Candidate, f candidateFilter) []*Candidate {
	res := make([]*Candidate, 0)
	for _, c := range candidates {
		if f(c) {
			res = append(res, c)
		}
	}
	return res
}

// compareVersions compares dotted numeric versions ("2.34" vs "2.4").
// Non-numeric components compare as zero; an empty string is the lowest.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = atoiPrefix(as[i])
		}
		if i < len(bs) {
			y = atoiPrefix(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func atoiPrefix(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func lowerBase(path string) string {
	return strings.ToLower(filepath.Base(path))
}

// parentDir returns the directory holding path, "" for top-level entries.
func parentDir(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return ""
	}
	return path[:i]
}

func joinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// stem returns the file name without its last extension.
func stem(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}

// eosFile adapts a pool entry to what pelican expects to be handed.
type eosFile struct {
	rs   io.ReadSeeker
	ra   io.ReaderAt
	size int64
	name string
}

func (f *eosFile) Read(b []byte) (int, error)                { return f.rs.Read(b) }
func (f *eosFile) Seek(off int64, whence int) (int64, error) { return f.rs.Seek(off, whence) }
func (f *eosFile) ReadAt(b []byte, off int64) (int, error)   { return f.ra.ReadAt(b, off) }
func (f *eosFile) Close() error                              { return nil }
func (f *eosFile) Stat() (os.FileInfo, error)                { return sizeFileInfo{name: f.name, size: f.size}, nil }

type sizeFileInfo struct {
	name string
	size int64
}

func (fi sizeFileInfo) Name() string       { return filepath.Base(fi.name) }
func (fi sizeFileInfo) Size() int64        { return fi.size }
func (fi sizeFileInfo) Mode() os.FileMode  { return 0644 }
func (fi sizeFileInfo) ModTime() time.Time { return time.Time{} }
func (fi sizeFileInfo) IsDir() bool        { return false }
func (fi sizeFileInfo) Sys() any           { return nil }
