package dash

// Reference game pages used to verify this detector:
//   https://t-bar.itch.io/spelling-shenanigans

// hashlinkDetector annotates executables next to hlboot.dat.
type hashlinkDetector struct{}

func (hashlinkDetector) detect(s *scan) error {
	for _, index := range s.filesNamed("hlboot.dat") {
		s.annotateNativesIn(parentDir(s.lowerFiles[index]), &EngineInfo{Engine: EngineHashLink})
	}
	return nil
}
