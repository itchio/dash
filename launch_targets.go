package dash

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/itchio/headway/state"
	"github.com/itchio/lake"
	"github.com/itchio/lake/tlc"
)

// LaunchTargetsSchemaVersion is recorded next to stored reports so consumers
// can detect LaunchTarget format changes.
const LaunchTargetsSchemaVersion = 1

// LaunchTarget is a candidate as stored in an upload's scan report. A missing
// size doesn't mean a directory: zero-byte files omit it too.
type LaunchTarget struct {
	Path        string       `json:"path"`
	Depth       int          `json:"depth"`
	Flavor      Flavor       `json:"flavor"`
	Arch        Arch         `json:"arch,omitempty"`
	Helper      string       `json:"helper,omitempty"`
	Size        int64        `json:"size,omitempty"`
	Sha256      string       `json:"sha256,omitempty"`
	Engine      *EngineInfo  `json:"engine,omitempty"`
	LinuxInfo   *LinuxInfo   `json:"linux_info,omitempty"`
	WindowsInfo *WindowsInfo `json:"windows_info,omitempty"`
	MacosInfo   *MacosInfo   `json:"macos_info,omitempty"`
}

// ScanLaunchTargets produces the launch report for an upload. It reads every
// candidate file in full to hash it, so run it at scan time, not when
// launching. Results are not filtered for the host.
func ScanLaunchTargets(root string, params ConfigureParams) ([]LaunchTarget, error) {
	container, pool, err := openConfigurePool(root, params)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	return ScanLaunchTargetsContainer(container, pool, params)
}

// ScanLaunchTargetsContainer is ScanLaunchTargets for a container and pool the
// caller already has. See ConfigureContainer.
func ScanLaunchTargetsContainer(container *tlc.Container, pool lake.Pool, params ConfigureParams) ([]LaunchTarget, error) {
	params.DeepProbe = true
	if params.Consumer == nil {
		params.Consumer = &state.Consumer{}
	}
	verdict, err := ConfigureContainer(container, pool, params)
	if err != nil {
		return nil, err
	}
	return launchTargetsFromVerdict(verdict, container, pool, params.Consumer), nil
}

func launchTargetsFromVerdict(verdict *Verdict, container *tlc.Container, pool lake.Pool, consumer *state.Consumer) []LaunchTarget {
	indices := make(map[string]int64, len(container.Files))
	for i, f := range container.Files {
		indices[f.Path] = int64(i)
	}
	targets := make([]LaunchTarget, 0, len(verdict.Candidates))
	for _, c := range verdict.Candidates {
		target := LaunchTarget{
			Path: c.Path, Depth: c.Depth, Flavor: c.Flavor, Arch: c.Arch,
			Helper: c.Helper, Engine: c.Engine, LinuxInfo: c.LinuxInfo,
			WindowsInfo: c.WindowsInfo, MacosInfo: c.MacosInfo,
		}
		if index, ok := indices[c.Path]; ok {
			target.Size = container.Files[index].Size
			target.Sha256 = launchTargetHash(pool, index, c.Path, consumer)
		}
		targets = append(targets, target)
	}
	return targets
}

func launchTargetHash(pool lake.Pool, index int64, path string, consumer *state.Consumer) string {
	r, err := pool.GetReadSeeker(index)
	if err != nil {
		consumer.Warnf("Couldn't open %s for hashing: %v", path, err)
		return ""
	}
	// A pool may return a cached reader previously used by a detector.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		consumer.Warnf("Couldn't seek %s for hashing: %v", path, err)
		return ""
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, r); err != nil {
		consumer.Warnf("While hashing %s: %v", path, err)
		return ""
	}
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
