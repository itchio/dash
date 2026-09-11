package dash

// openborDetector finds OpenBOR modules. Quake and others use the same
// "PACK" magic for their .pak files, so the signal is weak unless the pak
// sits in the Paks/ folder the engine loads from, in which case the engine
// next to that folder is annotated too.
//
// Details: "confidence" ("ext" outside a Paks/ folder).
type openborDetector struct{}

func (openborDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".pak") {
		if string(s.readHead(index, 4)) != "PACK" {
			continue
		}
		info := &EngineInfo{Engine: EngineOpenBOR}
		dir := parentDir(s.lowerFiles[index])
		if lowerBase(dir) == "paks" {
			s.annotateNativesIn(parentDir(dir), cloneEngine(info))
		} else {
			info.detail("confidence", "ext")
		}
		s.addFileCandidate(index, FlavorOpenBORPak, info)
	}
	return nil
}
