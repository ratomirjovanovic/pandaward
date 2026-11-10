package adapters

import (
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/rules"
)

// Supersessions maps a file language and a built-in rule to the bundled
// Semgrep rule that replaces it in files of that language. A bundled rule
// lists the built-in rules it replaces in its pandaward-supersedes
// metadata, only where it decides the same weakness more precisely (for
// example by following request data to the sink instead of matching one
// line). The replacement holds only when the semgrep adapter, on Semgrep or
// Opengrep, completed: otherwise the built-in rules are all there is.
type Supersessions map[string]map[string]string

// LoadSupersessions reads the bundled rules' pandaward-supersedes lists.
func LoadSupersessions() (Supersessions, error) {
	rs, err := rules.SemgrepRules()
	if err != nil {
		return nil, err
	}
	out := Supersessions{}
	for _, r := range rs {
		for _, lang := range r.Languages {
			for _, b := range r.Metadata.Supersedes {
				if out[lang] == nil {
					out[lang] = map[string]string{}
				}
				out[lang][b] = "semgrep." + r.ID
			}
		}
	}
	return out, nil
}

// By returns the bundled rule, as the semgrep adapter reports its id, that
// replaces a built-in signal in a file of the given language, or "".
func (s Supersessions) By(sig model.Signal, lang string) string {
	if sig.Collector != (codeAdapter{}).Name() {
		return ""
	}
	return s[lang][sig.RuleID]
}
