package dash

import (
	"github.com/itchio/lake"
	"github.com/pkg/errors"
	"howett.net/plist"
)

// readBundleExecutable returns the CFBundleExecutable declared by an
// Info.plist, or "" if the key is absent.
func readBundleExecutable(pool lake.Pool, fileIndex int64) (string, error) {
	r, err := pool.GetReadSeeker(fileIndex)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var info struct {
		CFBundleExecutable string `plist:"CFBundleExecutable"`
	}
	if err := plist.NewDecoder(r).Decode(&info); err != nil {
		return "", errors.WithStack(err)
	}
	return info.CFBundleExecutable, nil
}
