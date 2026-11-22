package dash

import (
	"bytes"
	"encoding/binary"
	"strings"
)

var oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Root storage class ids of Windows Installer packages (.msi) and patches
// (.msp), {000C1084-...} and {000C1086-...}, as stored on disk.
var msiClassIDs = [][]byte{
	{0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	{0x86, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
}

// sniffOLE tells an MSI from the other formats sharing the OLE compound
// file container (.doc, .xls, .ppt, .msg, thumbs.db) by the class id of
// the root storage. A package written without one still counts when it is
// named like an installer.
func sniffOLE(r *probeReader, lowerPath string) *Candidate {
	header := r.readAt(0, 52)
	if len(header) < 52 {
		return nil
	}

	sectorShift := binary.LittleEndian.Uint16(header[30:])
	if sectorShift != 9 && sectorShift != 12 {
		return nil
	}
	dirSector := int64(binary.LittleEndian.Uint32(header[48:]))
	rootOff := (dirSector + 1) << sectorShift

	root := r.readAt(rootOff, 96)
	if len(root) < 96 {
		return nil
	}
	clsid := root[80:96]

	for _, id := range msiClassIDs {
		if bytes.Equal(clsid, id) {
			return &Candidate{Flavor: FlavorMSI}
		}
	}

	named := strings.HasSuffix(lowerPath, ".msi") || strings.HasSuffix(lowerPath, ".msp")
	if named && bytes.Equal(clsid, make([]byte, 16)) {
		return &Candidate{Flavor: FlavorMSI}
	}
	return nil
}
