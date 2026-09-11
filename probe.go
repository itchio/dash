package dash

import (
	"errors"
	"io"
	"sort"
)

// DefaultMaxProbeBytes is the per-file read budget used when
// ConfigureParams.MaxProbeBytes is zero.
const DefaultMaxProbeBytes int64 = 1 << 20

var errProbeBudget = errors.New("dash: per-file probe budget exhausted")

// probeReader wraps a file's ReadSeeker and caps how much of the file the
// sniffers may look at. The budget counts distinct bytes, not reads: the
// magic matchers re-read the same window many times, and a trailer at the
// end of a large file costs only the trailer. A read that would push the
// covered span over the budget fails as a whole.
type probeReader struct {
	rs        io.ReadSeeker
	size      int64
	pos       int64
	remaining int64
	// merged, sorted, non-overlapping [start, end) spans already charged
	covered []span
}

type span struct{ start, end int64 }

var (
	_ io.ReadSeeker = (*probeReader)(nil)
	_ io.ReaderAt   = (*probeReader)(nil)
)

func newProbeReader(rs io.ReadSeeker, size int64, budget int64) *probeReader {
	if budget <= 0 {
		budget = DefaultMaxProbeBytes
	}
	return &probeReader{rs: rs, size: size, remaining: budget}
}

// charge records [start, end) as read, returning false (and recording
// nothing) if the uncovered part would exceed the budget.
func (p *probeReader) charge(start, end int64) bool {
	if end > p.size {
		end = p.size
	}
	if start >= end {
		return true
	}
	uncovered := end - start
	for _, s := range p.covered {
		lo, hi := max(s.start, start), min(s.end, end)
		if lo < hi {
			uncovered -= hi - lo
		}
	}
	if uncovered > p.remaining {
		return false
	}
	p.remaining -= uncovered

	merged := p.covered[:0]
	for _, s := range p.covered {
		if s.end < start || s.start > end {
			merged = append(merged, s)
			continue
		}
		start, end = min(start, s.start), max(end, s.end)
	}
	merged = append(merged, span{start, end})
	sort.Slice(merged, func(i, j int) bool { return merged[i].start < merged[j].start })
	p.covered = merged
	return true
}

func (p *probeReader) Read(b []byte) (int, error) {
	if !p.charge(p.pos, p.pos+int64(len(b))) {
		return 0, errProbeBudget
	}
	n, err := p.rs.Read(b)
	p.pos += int64(n)
	return n, err
}

func (p *probeReader) Seek(offset int64, whence int) (int64, error) {
	pos, err := p.rs.Seek(offset, whence)
	if err == nil {
		p.pos = pos
	}
	return pos, err
}

func (p *probeReader) ReadAt(b []byte, off int64) (int, error) {
	if off >= p.size {
		return 0, io.EOF
	}
	if !p.charge(off, off+int64(len(b))) {
		return 0, errProbeBudget
	}
	if _, err := p.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err := io.ReadFull(p.rs, b)
	p.pos += int64(n)
	// a short read at the end of the file is not an error to the magic
	// matchers, which probe past the end of small files all the time
	if n > 0 && (err == io.ErrUnexpectedEOF || err == io.EOF) {
		err = nil
	}
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

// readAt returns exactly n bytes at off, or nil if the file is too short,
// the budget is exhausted, or the read fails.
func (p *probeReader) readAt(off int64, n int) []byte {
	if off < 0 || n <= 0 || off+int64(n) > p.size {
		return nil
	}
	buf := make([]byte, n)
	got, err := p.ReadAt(buf, off)
	if got < n || (err != nil && err != io.EOF) {
		return nil
	}
	return buf
}

// readHead returns up to n bytes from the start of the file.
func (p *probeReader) readHead(n int) []byte {
	if int64(n) > p.size {
		n = int(p.size)
	}
	return p.readAt(0, n)
}

// readTail returns up to n bytes from the end of the file.
func (p *probeReader) readTail(n int) []byte {
	if int64(n) > p.size {
		n = int(p.size)
	}
	return p.readAt(p.size-int64(n), n)
}
