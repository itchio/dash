package dash

// Reference game pages used to verify this detector:
//   https://01010111.itch.io/bedhogg
//     .swf version 21
//   a projector exe: not yet verified against a live game

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"strconv"
	"strings"

	"github.com/ulikunitz/xz/lzma"
)

// swfDetector finds Flash movies and projector executables. A projector is
// the player with the movie appended and a marker + size as the last 8
// bytes; the exe is emitted as a payload since Ruffle can load it.
//
// Details: "projector" (true for executables), "width" and "height" (stage
// size in pixels), "frameRate", "frameCount". The stage size is what the
// header declares; a movie can still resize itself from script.
type swfDetector struct{}

const (
	swfProjectorMarker = 0xfa123456
	// enough compressed input to recover the few header bytes after the
	// signature, including a full deflate code table
	swfHeadWindow = 1024
	// RECT is at most 17 bytes, then UI16 frame rate and frame count
	swfHeadBytes = 21
)

type swfHeader struct {
	version    int
	width      int
	height     int
	frameRate  float64
	frameCount int
}

func (h *swfHeader) info() *EngineInfo {
	info := &EngineInfo{Engine: EngineFlash, Version: strconv.Itoa(h.version)}
	if h.width > 0 {
		info.detail("width", h.width)
		info.detail("height", h.height)
		info.detail("frameRate", h.frameRate)
		info.detail("frameCount", h.frameCount)
	}
	return info
}

// parseSWFHeader reads the signature, version and the movie header that
// follows the compressed boundary. head is the start of the file; the
// signature alone is enough for a result, the rest is best effort.
func parseSWFHeader(head []byte) *swfHeader {
	if len(head) < 4 {
		return nil
	}
	var body io.Reader
	switch string(head[0:3]) {
	case "FWS":
		if len(head) >= 8 {
			body = bytes.NewReader(head[8:])
		}
	case "CWS":
		if len(head) >= 8 {
			if z, err := zlib.NewReader(bytes.NewReader(head[8:])); err == nil {
				body = z
			}
		}
	case "ZWS":
		// u32 compressed length, 5 LZMA property bytes, then raw LZMA data
		// without an end marker. The decoder wants a .lzma header (props
		// plus u64 size) and checks that size against what it decodes, so
		// the movie's own length stands; the dictionary it would allocate
		// is pinned to the minimum, which cannot change the first bytes.
		if n := binary.LittleEndian.Uint32(head[4:8]); len(head) >= 17 && n >= 8+swfHeadBytes {
			hdr := make([]byte, 13)
			hdr[0] = head[12]
			binary.LittleEndian.PutUint32(hdr[1:], lzma.MinDictCap)
			binary.LittleEndian.PutUint64(hdr[5:], uint64(n)-8)
			cfg := lzma.ReaderConfig{DictCap: lzma.MinDictCap}
			if z, err := cfg.NewReader(io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(head[17:]))); err == nil {
				body = z
			}
		}
	default:
		return nil
	}
	h := &swfHeader{version: int(head[3])}
	if body == nil {
		return h
	}
	buf := make([]byte, swfHeadBytes)
	n, _ := io.ReadFull(body, buf)
	buf = buf[:n]
	br := swfBits{buf: buf}
	nbits := int(br.read(5))
	xmin := br.signed(nbits)
	xmax := br.signed(nbits)
	ymin := br.signed(nbits)
	ymax := br.signed(nbits)
	if br.overrun {
		return h
	}
	width, height := (xmax-xmin)/20, (ymax-ymin)/20
	if width <= 0 || height <= 0 || width > 1<<15 || height > 1<<15 {
		return h
	}
	off := br.byteOffset()
	if off+4 > len(buf) {
		return h
	}
	h.width, h.height = width, height
	h.frameRate = float64(binary.LittleEndian.Uint16(buf[off:])) / 256
	h.frameCount = int(binary.LittleEndian.Uint16(buf[off+2:]))
	return h
}

type swfBits struct {
	buf     []byte
	pos     int
	overrun bool
}

func (b *swfBits) read(n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		byteIdx := b.pos >> 3
		if byteIdx >= len(b.buf) {
			b.overrun = true
			return 0
		}
		bit := (b.buf[byteIdx] >> (7 - uint(b.pos&7))) & 1
		v = v<<1 | uint64(bit)
		b.pos++
	}
	return v
}

func (b *swfBits) signed(n int) int {
	v := b.read(n)
	if n > 0 && v&(1<<uint(n-1)) != 0 {
		return int(v) - 1<<uint(n)
	}
	return int(v)
}

func (b *swfBits) byteOffset() int {
	return (b.pos + 7) >> 3
}

func (swfDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".swf") {
		head := s.readHead(index, swfHeadWindow)
		if head == nil {
			head = s.readHead(index, 4)
		}
		h := parseSWFHeader(head)
		if h == nil {
			continue
		}
		s.addFileCandidate(index, FlavorSWF, h.info())
	}

	for _, c := range append([]*Candidate(nil), s.candidates...) {
		if c.Flavor != FlavorNativeWindows {
			continue
		}
		index, ok := s.file(strings.ToLower(c.Path))
		if !ok {
			continue
		}
		tail := s.readTail(index, 8)
		if tail == nil || binary.LittleEndian.Uint32(tail[0:4]) != swfProjectorMarker {
			continue
		}
		swfSize := int64(binary.LittleEndian.Uint32(tail[4:8]))
		start := c.Size - 8 - swfSize
		if swfSize <= 0 || start < 0 {
			continue
		}
		r, err := s.open(index)
		if err != nil {
			continue
		}
		h := parseSWFHeader(r.readAt(start, int(min(swfSize, swfHeadWindow))))
		if h == nil {
			continue
		}
		info := h.info()
		info.detail("projector", true)
		c.setEngine(cloneEngine(info))
		p := s.addFileCandidate(index, FlavorSWF, info)
		p.Mode = c.Mode
	}
	return nil
}
