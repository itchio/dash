package dash

import (
	"bufio"
	"io"
	"strings"
)

func sniffScript(r *probeReader, size int64) (*Candidate, error) {
	res := &Candidate{
		Flavor:     FlavorScript,
		ScriptInfo: &ScriptInfo{},
	}

	_, err := r.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(r)

	if s.Scan() {
		line := s.Text()
		if len(line) > 2 {
			// skip over the shebang
			interpreter := strings.TrimSpace(line[2:])
			// a shebang names its interpreter by absolute path; data files
			// that merely start with "#!" (e.g. RP6502 ROM images start
			// with "#!RP6502") are not scripts
			if !strings.HasPrefix(interpreter, "/") {
				return nil, nil
			}
			res.ScriptInfo.Interpreter = interpreter
		}
	}

	return res, nil
}
