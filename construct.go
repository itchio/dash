package dash

import (
	"strings"
)

// constructDetector annotates html candidates whose folder holds a
// Construct 2 or 3 runtime.
//
// Details: "variant" ("c2" or "c3"). Version is the major.
type constructDetector struct{}

func (constructDetector) detect(s *scan) error {
	for _, c := range s.candidates {
		if c.Flavor != FlavorHTML {
			continue
		}
		dir := parentDir(strings.ToLower(c.Path))
		var variant, version string
		switch {
		case s.hasFile(joinPath(dir, "c2runtime.js")):
			variant, version = "c2", "2"
		case s.hasFile(joinPath(dir, "c3runtime.js")), s.hasFile(joinPath(dir, "scripts/c3runtime.js")):
			variant, version = "c3", "3"
		default:
			continue
		}
		info := &EngineInfo{Engine: EngineConstruct, Version: version}
		info.detail("variant", variant)
		c.setEngine(info)
	}
	return nil
}
