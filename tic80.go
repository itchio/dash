package dash

// tic80Detector finds .tic cartridges. The format is a chunk list with no
// magic, so the name is all there is.
//
// Details: "confidence" ("ext").
type tic80Detector struct{}

func (tic80Detector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".tic") {
		info := &EngineInfo{Engine: EngineTIC80}
		info.detail("confidence", "ext")
		s.addFileCandidate(index, FlavorTIC80Cart, info)
	}
	return nil
}
