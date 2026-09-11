package dash

// pyxelDetector finds .pyxapp bundles, which are zips of the app folder.
type pyxelDetector struct{}

func (pyxelDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".pyxapp") {
		if string(s.readHead(index, 4)) != "PK\x03\x04" {
			continue
		}
		s.addFileCandidate(index, FlavorPyxelApp, &EngineInfo{Engine: EnginePyxel})
	}
	return nil
}
