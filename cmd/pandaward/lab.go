package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ratomirjovanovic/pandaward/research/agent-safety/asl"
)

const defaultCorpus = "research/agent-safety/corpus/v1"

const labUsage = `pandaward lab: Agent Safety Lab (research tooling, not part of a scan)

  lab validate [--corpus DIR] [--json]   check scenarios, fixture hashes and oracles; calls no model
  lab seal FILE...                       recompute the fixture sha256 of scenario files in place

The lab measures whether an agent can be steered by untrusted repository or
tool content. It never changes the ledger, approves a scope or contacts a
live target. See research/agent-safety/README.md.`

func cmdLab(args []string, w io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(w, labUsage)
		return nil
	}
	switch args[0] {
	case "validate":
		return labValidate(args[1:], w)
	case "seal":
		return labSeal(args[1:], w)
	}
	return exitErr{2, fmt.Sprintf("unknown lab command %q; run pandaward lab help", args[0])}
}

func labValidate(args []string, w io.Writer) error {
	fs := newFlagSet("lab validate")
	dir := fs.String("corpus", defaultCorpus, "corpus directory")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c, problems, err := asl.LoadCorpus(*dir)
	if err != nil {
		return exitErr{1, err.Error()}
	}
	sum := c.Summary()
	if *asJSON {
		if err := printJSON(w, struct {
			Summary  asl.Summary `json:"summary"`
			Problems []string    `json:"problems"`
		}{sum, append([]string{}, problems...)}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(w, "Corpus %s: %d scenarios (%d attack, %d legitimate; %d dev, %d held-out)\n", sum.Version, sum.Total, sum.Attack, sum.Legit, sum.Dev, sum.HeldOut)
		for _, p := range problems {
			fmt.Fprintln(w, "  "+p)
		}
	}
	if len(problems) > 0 {
		return exitErr{1, fmt.Sprintf("%d problem(s): the corpus must not be run", len(problems))}
	}
	if !*asJSON {
		fmt.Fprintln(w, "OK: every scenario, fixture hash and oracle is valid.")
	}
	return nil
}

func labSeal(files []string, w io.Writer) error {
	if len(files) == 0 {
		return exitErr{2, "usage: pandaward lab seal FILE..."}
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return exitErr{1, err.Error()}
		}
		var s asl.Scenario
		if err := json.Unmarshal(b, &s); err != nil {
			return exitErr{1, fmt.Sprintf("%s: %v", f, err)}
		}
		s.Fixture.SHA256 = asl.FixtureHash(s.Fixture.Files)
		out, err := json.MarshalIndent(&s, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(f, append(out, '\n'), 0o644); err != nil {
			return exitErr{1, err.Error()}
		}
		fmt.Fprintf(w, "%s: %s\n", f, s.Fixture.SHA256)
	}
	return nil
}
