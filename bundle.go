package dash

import (
	"bytes"
	"io"

	"github.com/itchio/lake"
	"github.com/pkg/errors"
	"howett.net/plist"
)

// maxBundlePlistSize bounds Info.plist parsing. Real ones are a few KB; the
// plist parsers recurse per nesting level, so an unbounded file could
// overflow the stack.
const maxBundlePlistSize = 256 * 1024

// readBundleExecutable returns the CFBundleExecutable declared by an
// Info.plist, or "" if the key is absent.
func readBundleExecutable(pool lake.Pool, fileIndex int64) (string, error) {
	r, err := pool.GetReadSeeker(fileIndex)
	if err != nil {
		return "", errors.WithStack(err)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBundlePlistSize+1))
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(data) > maxBundlePlistSize {
		return "", errors.Errorf("Info.plist exceeds %d bytes", maxBundlePlistSize)
	}
	var info struct {
		CFBundleExecutable string `plist:"CFBundleExecutable"`
	}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&info); err != nil {
		return "", errors.WithStack(err)
	}
	return info.CFBundleExecutable, nil
}
