package dash_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/itchio/dash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ROM3DS(t *testing.T) {
	// Synthetic CIA with unaligned sections, including optional metadata.
	cia := make([]byte, 0x2141)
	binary.LittleEndian.PutUint32(cia, 0x2020)
	for _, offset := range []int{8, 12, 16, 20} {
		binary.LittleEndian.PutUint32(cia[offset:], 1)
	}
	binary.LittleEndian.PutUint64(cia[24:], 1)
	noMeta := append([]byte(nil), cia[:0x2101]...)
	binary.LittleEndian.PutUint32(noMeta[20:], 0)
	homebrew := make([]byte, 0x20)
	copy(homebrew, "3DSX")
	binary.LittleEndian.PutUint16(homebrew[4:], 0x20)
	extended := append(append([]byte(nil), homebrew...), make([]byte, 12)...)
	binary.LittleEndian.PutUint16(extended[4:], 0x2c)
	cartridge := make([]byte, 0x200)
	copy(cartridge[0x100:], "NCSD")
	mutate := func(data []byte, offset int, value uint64, width int) []byte {
		data = append([]byte(nil), data...)
		for i := 0; i < width; i++ {
			data[offset+i] = byte(value >> (i * 8))
		}
		return data
	}
	tests := []struct {
		name   string
		data   []byte
		format string
	}{
		{"game.cia", cia, "cia"},
		{"no-meta.CIA", noMeta, "cia"},
		{"homebrew.3dsx", homebrew, "3dsx"},
		{"extended.3DSX", extended, "3dsx"},
		{"cartridge.3ds", cartridge, "3ds"},
		{"cartridge.cci", cartridge, "cci"},
		{"model.3ds", []byte{0x4d, 0x4d, 6, 0, 0, 0}, ""},
		{"fake.cci", make([]byte, 0x200), ""},
		{"short.3ds", cartridge[:0x104], ""},
		{"empty.cia", nil, ""},
		{"short.cia", cia[:31], ""},
		{"truncated.cia", cia[:len(cia)-1], ""},
		{"missing-content.cia", mutate(cia, 24, 0, 8), ""},
		{"missing-ticket.cia", mutate(cia, 12, 0, 4), ""},
		{"overflow.cia", mutate(cia, 24, ^uint64(0), 8), ""},
		{"bad-header.cia", mutate(cia, 0, 0x20, 4), ""},
		{"bad-type.cia", mutate(cia, 4, 1, 2), ""},
		{"versioned.cia", mutate(cia, 6, 1, 2), "cia"},
		{"short.3dsx", homebrew[:4], ""},
		{"bad-magic.3dsx", mutate(homebrew, 0, 0, 4), ""},
		{"bad-header.3dsx", mutate(homebrew, 4, 0x10, 2), ""},
		{"truncated-header.3dsx", extended[:0x20], ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, tt.name), tt.data, 0644))
			v, err := dash.Configure(dir, configureParams(t))
			require.NoError(t, err)
			if tt.format == "" {
				assert.Empty(t, v.Candidates)
				return
			}
			require.Len(t, v.Candidates, 1)
			c := v.Candidates[0]
			assert.Equal(t, dash.FlavorROM, c.Flavor)
			require.NotNil(t, c.Engine)
			assert.Equal(t, dash.EngineROM, c.Engine.Engine)
			assert.Equal(t, "3ds", detail(c, "system"))
			assert.Equal(t, tt.format, detail(c, "format"))
			assert.Nil(t, detail(c, "confidence"))
			filtered := v.Filter(makeConsumer(t), dash.FilterParams{OS: "linux", Arch: "amd64", Runtimes: []dash.Flavor{"rom:3ds"}})
			assert.Equal(t, []string{tt.name}, candidatePaths(filtered))
		})
	}
}
