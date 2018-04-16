package dash

import (
	"io"

	"github.com/fasterthanlime/spellbook"
	"github.com/fasterthanlime/wizardry/wizardry/wizutil"
)

func sniffFatMach(r io.ReadSeeker, size int64) (*Candidate, error) {
	ra := &readerAtFromSeeker{r}

	sr := wizutil.NewSliceReader(ra, 0, size)
	spell := spellbook.Identify(sr, 0)

	if spellHas(spell, "compiled Java class data,") {
		// nevermind
		return nil, nil
	}

	return &Candidate{
		Flavor: FlavorNativeMacos,
		Spell:  spell,
	}, nil
}
