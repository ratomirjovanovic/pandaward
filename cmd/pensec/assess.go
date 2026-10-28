package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/internal/report"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

const banner = `  ____            ____
 |  _ \ ___ _ __ / ___|  ___  ___
 | |_) / _ \ '_ \\___ \ / _ \/ __|
 |  __/  __/ | | |___) |  __/ (__
 |_|   \___|_| |_|____/ \___|\___|
`

// bar draws a fixed-width progress bar. ASCII mode avoids block characters
// for terminals that cannot show them.
func bar(done, total, width int, ascii bool) string {
	if total <= 0 {
		total = 1
	}
	if done > total {
		done = total
	}
	n := done * width / total
	if done > 0 && n == 0 {
		n = 1 // anything above zero stays visible
	}
	full, empty := "█", "░"
	if ascii {
		full, empty = "#", "-"
	}
	return strings.Repeat(full, n) + strings.Repeat(empty, width-n)
}

// progressView prints one line per update; on a terminal it rewrites the
// line in place instead.
type progressView struct {
	w     io.Writer
	tty   bool
	ascii bool
	done  int
	total int
	last  string
}

func (p *progressView) step(label string) {
	if p.done < p.total {
		p.done++
	}
	line := fmt.Sprintf("  [%s] %3d%%  %s", bar(p.done, p.total, 28, p.ascii), p.done*100/p.total, label)
	if p.tty {
		pad := ""
		if n := len([]rune(p.last)) - len([]rune(line)); n > 0 {
			pad = strings.Repeat(" ", n)
		}
		fmt.Fprint(p.w, "\r"+line+pad)
	} else {
		fmt.Fprintln(p.w, line)
	}
	p.last = line
}

func (p *progressView) finish() {
	if p.tty {
		fmt.Fprintln(p.w)
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func cmdAssess(ctx context.Context, args []string, w io.Writer) error {
	fs, root := newFS("assess")
	asJSON := fs.Bool("json", false, "JSON summary instead of the progress view")
	ascii := fs.Bool("ascii", os.Getenv("PENSEC_ASCII") != "", "ASCII progress bars (also PENSEC_ASCII=1)")
	noBanner := fs.Bool("no-banner", false, "skip the banner")
	formats := fs.String("format", "html,markdown,json,sarif", "report formats")
	failLevel := fs.String("fail-on", "", "exit 4 if open confirmed findings at or above this severity exist")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	r := *root
	if r == "" {
		r = "."
	}
	// The classic Windows console often lacks block characters; Windows
	// Terminal (WT_SESSION) and other terminals show them.
	if runtime.GOOS == "windows" && isTerminal(w) && os.Getenv("WT_SESSION") == "" {
		*ascii = true
	}
	if !*asJSON && !*noBanner {
		fmt.Fprint(w, banner)
		fmt.Fprintf(w, "\n  PenSec %s - local, evidence-based security assessment\n", version.Version)
		fmt.Fprintln(w, "  by Ratomir Jovanovic - https://github.com/ratomirjovanovic/pensec")
		fmt.Fprintln(w, "  Passive: reads the repository, runs no project code, sends nothing to any target.")
		fmt.Fprintln(w)
	}
	e, created, err := engine.Init(r, false)
	if err != nil {
		return err
	}
	defer e.Close()

	view := &progressView{w: w, tty: isTerminal(w), ascii: *ascii, total: len(e.Cfg.Scan.Adapters) + 4}
	if *asJSON {
		view.w = io.Discard
	}
	if created {
		view.step("initialized .pensec/ (config, private ledger)")
	} else {
		view.step("using existing .pensec/")
	}
	progress := func(m string) {
		switch {
		case strings.HasPrefix(m, "inventory:"):
			view.step("inventory (read-only walk)")
		case strings.HasPrefix(m, "adapter: "):
			view.step(strings.TrimPrefix(m, "adapter: "))
		case strings.HasPrefix(m, "findings:"):
			view.step("findings, evidence and edges")
		}
	}
	res, err := e.Scan(ctx, progress)
	if err != nil {
		view.finish()
		return err
	}
	rep, err := report.Build(e)
	if err != nil {
		view.finish()
		return err
	}
	paths, err := report.Write(rep, report.DefaultDir(e.Root), strings.Split(*formats, ","))
	if err != nil {
		view.finish()
		return err
	}
	view.done = view.total - 1
	view.step("reports written")
	view.finish()

	if *asJSON {
		if err := printJSON(w, map[string]any{"scan": res, "reports": paths}); err != nil {
			return err
		}
		return failOn(e, *failLevel)
	}
	printSummary(w, res, rep, paths, *ascii)
	return failOn(e, *failLevel)
}

func printSummary(w io.Writer, res *engine.ScanResult, rep *report.Report, paths []string, ascii bool) {
	rule := strings.Repeat("=", 64)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  "+rule)
	fmt.Fprintf(w, "  Assessment %s: %s\n", res.AssessmentID, res.Status)
	fmt.Fprintln(w, "  "+rule)

	c := res.Coverage
	fmt.Fprintf(w, "\n  Decisive coverage  [%s] %3.0f%%  (%d of %d applicable controls PASS or FAIL)\n",
		bar(c.Decisive, c.Applicable, 24, ascii), c.Ratio*100, c.Decisive, c.Applicable)
	fmt.Fprintf(w, "  Cross-domain edges  %d (%d verified, %d failed, %d open)\n", c.EdgesTotal, c.EdgesVerified, c.EdgesFailed, c.EdgesOpen)

	conf, susp := rep.Confirmed(), rep.Suspected()
	bySev := map[model.Severity]int{}
	for _, f := range conf {
		bySev[f.Severity]++
	}
	fmt.Fprintf(w, "\n  Findings  %d confirmed, %d suspected (hypotheses, need review)\n", len(conf), len(susp))
	for _, s := range []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo} {
		if n := bySev[s]; n > 0 {
			fmt.Fprintf(w, "    %-9s %3d  %s\n", s, n, bar(n, len(conf), 20, ascii))
		}
	}
	sort.SliceStable(conf, func(i, j int) bool {
		return model.SeverityRank(conf[i].Severity) > model.SeverityRank(conf[j].Severity)
	})
	if len(conf) > 0 {
		fmt.Fprintln(w, "\n  Fix first")
		for i, f := range conf {
			if i == 5 {
				fmt.Fprintf(w, "    ... %d more (pensec findings)\n", len(conf)-5)
				break
			}
			loc := f.File
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
			}
			fmt.Fprintf(w, "    %s  %-8s %s\n              %s  [%s]\n", f.ID, f.Severity, redact.Line(f.Title), redact.Line(loc), f.ControlID)
		}
	}

	gaps := map[model.Status]int{}
	for _, ctl := range rep.Untested() {
		gaps[ctl.Status]++
	}
	var gs []string
	for s, n := range gaps {
		gs = append(gs, fmt.Sprintf("%s %d", s, n))
	}
	sort.Strings(gs)
	if len(gs) > 0 {
		fmt.Fprintf(w, "\n  Not decided (never counted as secure): %s\n", strings.Join(gs, ", "))
	}
	if len(res.Errors) > 0 {
		fmt.Fprintln(w, "  Adapter errors make this assessment INCOMPLETE:")
		for _, e := range res.Errors {
			fmt.Fprintln(w, "    "+redact.Line(e))
		}
	}

	fmt.Fprintln(w, "\n  Reports")
	for _, p := range paths {
		fmt.Fprintln(w, "    "+redact.Line(p))
	}
	fmt.Fprintln(w, "\n  Next")
	fmt.Fprintln(w, "    /pensec:review     specialist review of what automation could not decide")
	fmt.Fprintln(w, "    pensec fix-plan    ordered fixes, then pensec retest --changed")
	fmt.Fprintln(w, "    pensec feedback    tell us about a wrong or missed finding")
	fmt.Fprintf(w, "\n  Catalog %s. An automated technical assessment, not a certification or a penetration test.\n", catalog.Version)
}
