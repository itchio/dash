package dash

import "strings"

// defoldDetector annotates executables next to game.projectc and a
// game.arcd/game.arci archive pair, and html candidates next to
// dmloader.js. The engine version only lives in the dmengine binary, so
// none is reported.
//
// Details: "platform" ("web") for html builds.
type defoldDetector struct{}

func (defoldDetector) detect(s *scan) error {
	for _, index := range s.filesNamed("game.projectc") {
		dir := parentDir(s.lowerFiles[index])
		if !s.hasFile(joinPath(dir, "game.arcd")) && !s.hasFile(joinPath(dir, "game.arci")) {
			continue
		}
		s.annotateNativesIn(dir, &EngineInfo{Engine: EngineDefold})
	}
	for _, c := range s.candidates {
		if c.Flavor != FlavorHTML || !s.hasFile(joinPath(parentDir(strings.ToLower(c.Path)), "dmloader.js")) {
			continue
		}
		info := &EngineInfo{Engine: EngineDefold}
		info.detail("platform", "web")
		c.setEngine(info)
	}
	return nil
}
