package dash

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// buildOLE makes the start of a compound file: a header and a directory
// sector whose root entry carries clsid.
func buildOLE(sectorShift uint16, clsid []byte) []byte {
	sectorSize := 1 << sectorShift
	const dirSector = 2

	b := make([]byte, (dirSector+2)*sectorSize)
	copy(b, oleMagic)
	binary.LittleEndian.PutUint16(b[30:], sectorShift)
	binary.LittleEndian.PutUint32(b[48:], dirSector)

	root := b[(dirSector+1)*sectorSize:]
	root[66] = 5
	copy(root[80:], clsid)
	return b
}

func Test_SniffOLE(t *testing.T) {
	wordClassID := []byte{0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	noClassID := make([]byte, 16)

	cases := []struct {
		desc  string
		name  string
		data  []byte
		isMSI bool
	}{
		{"msi", "setup.msi", buildOLE(9, msiClassIDs[0]), true},
		{"msi with 4096-byte sectors", "setup.msi", buildOLE(12, msiClassIDs[0]), true},
		{"msi under another name", "data.bin", buildOLE(9, msiClassIDs[0]), true},
		{"patch", "update.msp", buildOLE(9, msiClassIDs[1]), true},
		{"msi without a class id", "setup.msi", buildOLE(9, noClassID), true},
		{"word document", "manual.doc", buildOLE(9, wordClassID), false},
		{"word document named like an installer", "manual.msi", buildOLE(9, wordClassID), false},
		{"other file without a class id", "thumbs.db", buildOLE(9, noClassID), false},
		{"truncated", "setup.msi", buildOLE(9, msiClassIDs[0])[:600], false},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			res, err := Sniff(bytes.NewReader(c.data), c.name, int64(len(c.data)))
			assert.NoError(t, err)
			if c.isMSI {
				if assert.NotNil(t, res) {
					assert.Equal(t, FlavorMSI, res.Flavor)
				}
			} else {
				assert.Nil(t, res)
			}
		})
	}
}
