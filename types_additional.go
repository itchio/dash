package dash

// These are in a separate file so they don't get picked up by
// generous, see github.com/itchio/butler/butlerd/generous
//
// It's not great, but /shrug

type VerdictStats struct {
	NumSniffs   int
	SniffsByExt map[string]int
}
