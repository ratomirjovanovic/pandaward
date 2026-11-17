package asl

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// sensitive patterns a public report must not contain.
var sensitiveRe = []*regexp.Regexp{
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`(?i)canary[-_a-z0-9]*[=:] ?\S{6,}`),
	regexp.MustCompile(`(?i)\b[a-z]:\\(users|windows)\\`),
	regexp.MustCompile(`/(home|Users)/[A-Za-z0-9._-]+/`),
	regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
	regexp.MustCompile(`(?i)authorization: ?bearer`),
}

// CheckPublic fails when text contains something that must not be published.
func CheckPublic(text string) error {
	for _, re := range sensitiveRe {
		if m := re.FindString(text); m != "" {
			return fmt.Errorf("public report refused: it contains %q, which matches a sensitive pattern", truncate(m, 24))
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func pct(r Rate) string {
	if r.N == 0 {
		return "n/a (0 episodes)"
	}
	return fmt.Sprintf("%.0f%% [%.0f-%.0f%%] (%d/%d)", 100*r.P, 100*r.Lo, 100*r.Hi, r.K, r.N)
}

// ReportOptions tunes the generated report.
type ReportOptions struct {
	Public bool
	Spend  *SpendReport
}

// Markdown renders the report of a run from its manifest and episodes only,
// so every number traces to a run. It states the provider on top, publishes
// null results as they are, and lists limitations. With Public, it refuses
// when a sensitive pattern is found.
func Markdown(m Manifest, rs []EpisodeResult, opt ReportOptions) (string, error) {
	var b strings.Builder
	rep := Score(rs)
	label := map[string]string{
		ProviderMock: "MOCK: scripted agents, not a model. These numbers check the harness and say nothing about any model.",
		ProviderAPI:  "API track: a model with identical, controlled tools in every arm.",
		ProviderCC:   "Claude Code end to end: a different system prompt and tools; not comparable to the API track.",
	}[m.Provider]
	fmt.Fprintf(&b, "# Agent Safety Lab report: run %s\n\n", m.Run)
	fmt.Fprintf(&b, "> **%s**\n\n", label)
	fmt.Fprintf(&b, "| | |\n|---|---|\n| Provider | %s |\n", m.Provider)
	if m.Model != "" {
		fmt.Fprintf(&b, "| Model | %s |\n", m.Model)
	}
	if m.MonitorModel != "" {
		fmt.Fprintf(&b, "| Monitor model | %s |\n", m.MonitorModel)
	}
	fmt.Fprintf(&b, "| Corpus | %s, sha256 %s |\n| Split | %s |\n| Scenarios | %d |\n| Arms | %v |\n| Repetitions | %d |\n| Seed | %d |\n| Planned episodes | %d |\n| Episodes recorded | %d |\n| PandaWard | %s |\n\n",
		m.CorpusVer, m.CorpusSHA256, m.Split, m.Scenarios, m.Arms, m.Reps, m.Seed, m.Planned, len(rs), m.Version)
	if len(rs) < m.Planned {
		fmt.Fprintf(&b, "**The run is incomplete: %d of %d planned episodes.**\n\n", len(rs), m.Planned)
	}

	b.WriteString("## Per arm\n\nIntervals are 95% Wilson. Rates use VALID episodes; INVALID ones are listed and never dropped.\n\n")
	b.WriteString("| Arm | Episodes | Invalid | Attack success | Attack attempted | Utility on controls | False assurance |\n|---|---|---|---|---|---|---|\n")
	for _, arm := range Arms {
		c := rep.Arms[arm]
		if c == nil {
			continue
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %s | %s |\n", arm, c.Total, c.Invalid, pct(c.AttackSuccess), pct(c.Attempted), pct(c.Utility), pct(c.FalseAssurance))
	}
	b.WriteString("\n## Per family and arm (attack success)\n\n| Family | " + strings.Join(armNames(rep), " | ") + " |\n|---|" + strings.Repeat("---|", len(armNames(rep))) + "\n")
	fams := map[string]bool{}
	for _, byFam := range rep.Families {
		for f := range byFam {
			fams[f] = true
		}
	}
	var fl []string
	for f := range fams {
		fl = append(fl, f)
	}
	sort.Strings(fl)
	for _, f := range fl {
		fmt.Fprintf(&b, "| %s %s |", f, Families[f])
		for _, arm := range Arms {
			if c := rep.Families[arm][f]; c != nil {
				fmt.Fprintf(&b, " %s |", pct(c.AttackSuccess))
			} else if rep.Arms[arm] != nil {
				b.WriteString(" n/a |")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## Paired comparisons\n\nDifference in attack success rate on the same scenario and repetition (first arm minus second; positive means the first was breached more often), 95% paired bootstrap interval.\n\n| Comparison | Pairs | Difference | Interval | Only first breached | Only second breached |\n|---|---|---|---|---|---|\n")
	for _, p := range [][2]Arm{{ArmA, ArmB}, {ArmB, ArmC}, {ArmC, ArmD}, {ArmA, ArmD}} {
		if rep.Arms[p[0]] == nil || rep.Arms[p[1]] == nil {
			continue
		}
		d := PairedDiff(rs, p[0], p[1], m.Seed, 4000)
		if d.Pairs == 0 {
			fmt.Fprintf(&b, "| %s vs %s | 0 | n/a | n/a | | |\n", p[0], p[1])
			continue
		}
		fmt.Fprintf(&b, "| %s vs %s | %d | %+.2f | [%+.2f, %+.2f] | %d | %d |\n", p[0], p[1], d.Pairs, d.Diff, d.Lo, d.Hi, d.OnlyAWins, d.OnlyBWins)
	}
	inv := map[string]int{}
	for _, r := range rs {
		if r.Status != StatusValid {
			inv[truncate(r.InvalidReason, 70)]++
		}
	}
	b.WriteString("\n## Invalid episodes\n\n")
	if len(inv) == 0 {
		b.WriteString("None.\n")
	} else {
		var ks []string
		for k := range inv {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Fprintf(&b, "- %d x %s\n", inv[k], k)
		}
	}
	if opt.Spend != nil {
		fmt.Fprintf(&b, "\n## Cost\n\nSpent %s of the %s cap over %d recorded calls", opt.Spend.Spent.USD(), opt.Spend.Cap.USD(), opt.Spend.Calls)
		var ms []string
		for k := range opt.Spend.ByModel {
			ms = append(ms, k)
		}
		sort.Strings(ms)
		for _, k := range ms {
			fmt.Fprintf(&b, "; %s: %s", k, opt.Spend.ByModel[k].USD())
		}
		b.WriteString(".\n")
	}
	b.WriteString(`
## Limitations

- Scenarios are synthetic and the corpus is small; intervals are wide and a rate of zero does not mean a defense is complete.
- Attack success is judged on the simulated effect journal against the oracle, not on an opinion of a model.
- Arms differ only in enforcement; the tools and the system prompt are identical.
- A null or negative result is a result and is published as measured.
- Rates describe this model, this prompt and this corpus on the run dates; they are not a property of PandaWard or of the model in general.
`)
	out := b.String()
	if opt.Public {
		if err := CheckPublic(out); err != nil {
			return "", err
		}
	}
	return out, nil
}

func armNames(rep Report) []string {
	var out []string
	for _, a := range Arms {
		if rep.Arms[a] != nil {
			out = append(out, "Arm "+string(a))
		}
	}
	return out
}
