package asl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Corpus is a loaded, validated set of scenarios.
type Corpus struct {
	Version   string
	Scenarios []*Scenario
}

// Summary counts scenarios by family, kind and split.
type Summary struct {
	Version string         `json:"version"`
	Total   int            `json:"total"`
	Attack  int            `json:"attack"`
	Legit   int            `json:"legitimate"`
	Dev     int            `json:"dev"`
	HeldOut int            `json:"heldout"`
	ByFam   map[string]int `json:"by_family"`
}

type corpusFile struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}

// LoadCorpus reads corpus.json and every scenario file below dir and
// validates them. It never calls a model. The returned problems are
// everything wrong with the corpus; when there are any, the corpus must not
// be run. Scenario files are strict: an unknown field is a problem, so a
// typo in an oracle cannot silently weaken a scenario.
func LoadCorpus(dir string) (*Corpus, []string, error) {
	var problems []string
	raw, err := os.ReadFile(filepath.Join(dir, "corpus.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("read corpus.json: %w", err)
	}
	var cf corpusFile
	if err := strictJSON(raw, &cf); err != nil {
		return nil, nil, fmt.Errorf("corpus.json: %w", err)
	}
	if cf.Schema != Schema || strings.TrimSpace(cf.Version) == "" {
		problems = append(problems, fmt.Sprintf("corpus.json: schema must be %q and version set", Schema))
	}
	c := &Corpus{Version: cf.Version}
	var paths []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") && filepath.Base(p) != "corpus.json" {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		var s Scenario
		if err := strictJSON(b, &s); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", filepath.Base(p), err))
			continue
		}
		if want := s.ID + ".json"; filepath.Base(p) != want {
			problems = append(problems, fmt.Sprintf("%s: the file of scenario %s must be named %s", filepath.Base(p), s.ID, want))
		}
		problems = append(problems, s.Validate()...)
		c.Scenarios = append(c.Scenarios, &s)
	}
	problems = append(problems, c.validateSet()...)
	return c, problems, nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("more than one JSON document")
	}
	return nil
}

// validateSet checks what only the whole corpus can show: duplicate ids and
// mechanisms, and that every control mirrors a real attack of its family.
func (c *Corpus) validateSet() []string {
	var p []string
	ids := map[string]*Scenario{}
	mech := map[string]string{}
	for _, s := range c.Scenarios {
		if prev, dup := ids[s.ID]; dup && prev != s {
			p = append(p, fmt.Sprintf("%s: duplicate id", s.ID))
		}
		ids[s.ID] = s
		if s.Kind == KindAttack {
			key := s.Family + "|" + normalize(s.Mechanism)
			if other, dup := mech[key]; dup {
				p = append(p, fmt.Sprintf("%s: same mechanism as %s; paraphrases are not independent scenarios", s.ID, other))
			}
			mech[key] = s.ID
		}
	}
	for _, s := range c.Scenarios {
		if s.Kind != KindLegitimate || s.MatchedWith == "" {
			continue
		}
		a, ok := ids[s.MatchedWith]
		switch {
		case !ok:
			p = append(p, fmt.Sprintf("%s: matched_with %s does not exist", s.ID, s.MatchedWith))
		case a.Kind != KindAttack:
			p = append(p, fmt.Sprintf("%s: matched_with %s is not an attack scenario", s.ID, s.MatchedWith))
		case a.Family != s.Family:
			p = append(p, fmt.Sprintf("%s: matched_with %s is in family %s", s.ID, s.MatchedWith, a.Family))
		}
	}
	sort.Strings(p)
	return p
}

func normalize(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// Summary counts the corpus.
func (c *Corpus) Summary() Summary {
	sum := Summary{Version: c.Version, Total: len(c.Scenarios), ByFam: map[string]int{}}
	for _, s := range c.Scenarios {
		if s.Kind == KindAttack {
			sum.Attack++
		} else {
			sum.Legit++
		}
		if s.Split == SplitDev {
			sum.Dev++
		} else {
			sum.HeldOut++
		}
		sum.ByFam[s.Family]++
	}
	return sum
}
