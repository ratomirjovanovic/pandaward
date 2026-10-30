package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/feedback"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// ghRunner runs the GitHub CLI; nil when gh is missing or not signed in.
// A variable so tests can stand in for GitHub.
var ghRunner = func() feedback.Runner {
	if _, err := exec.LookPath("gh"); err != nil {
		return nil
	}
	if exec.Command("gh", "auth", "status").Run() != nil {
		return nil
	}
	return func(stdin string, args ...string) (string, error) {
		cmd := exec.Command("gh", args...)
		cmd.Stdin = strings.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("gh %s: %v: %s", args[0], err, strings.TrimSpace(redact.Line(errb.String())))
		}
		return out.String(), nil
	}
}

const feedbackWhy = "PandaWard is open source and its rules are fixed from these reports. Each report holds the rule, counts, file types and versions only: no paths, no code."

func modeLine(st feedback.State) string {
	if st.Mode == "" {
		return "Feedback mode: not chosen yet (behaves like ask). Choose with: pandaward feedback mode ask|batch|off"
	}
	return fmt.Sprintf("Feedback mode: %s (chosen %s)", st.Mode, strings.SplitN(st.ModeSet, "T", 2)[0])
}

// feedbackFlow handles feedback mode, pending and submit.
func feedbackFlow(e *engine.Engine, sub string, pos []string, asJSON, yes bool, stdin io.Reader, w io.Writer) error {
	st, gs, err := e.PendingFeedback()
	if err != nil {
		return err
	}
	switch sub {
	case "mode":
		if len(pos) == 1 {
			if err := st.SetMode(pos[0], time.Now()); err != nil {
				return exitErr{2, err.Error()}
			}
			if err := feedback.SaveState(e.Private(), st); err != nil {
				return err
			}
		} else if len(pos) > 1 {
			return exitErr{2, "usage: pandaward feedback mode [ask|batch|off]"}
		}
		if asJSON {
			return printJSON(w, map[string]any{"mode": st.Mode, "mode_set_at": st.ModeSet, "pending": len(gs)})
		}
		fmt.Fprintln(w, modeLine(st))
		if st.Mode == "" {
			fmt.Fprintln(w, "  ask    offer each report on its own")
			fmt.Fprintln(w, "  batch  prepare all reports after triage, send them after one confirmation")
			fmt.Fprintln(w, "  off    never offer reports")
			fmt.Fprintln(w, feedbackWhy)
		}
		return nil
	case "pending":
		if asJSON {
			return printJSON(w, map[string]any{"mode": st.Mode, "reports": gs, "gh_ready": ghRunner() != nil})
		}
		fmt.Fprintln(w, modeLine(st))
		printPending(w, gs)
		if len(gs) > 0 {
			fmt.Fprintln(w, "\n"+feedbackWhy)
			fmt.Fprintln(w, "Send them with: pandaward feedback submit")
		}
		return nil
	}
	// submit
	if len(gs) == 0 {
		fmt.Fprintln(w, "No reports to send.")
		return nil
	}
	printPending(w, gs)
	if !yes {
		if !isInteractive() {
			return exitErr{3, "feedback submit sends reports to GitHub: run it yourself in a terminal, or pass --yes after the user has seen the reports above"}
		}
		fmt.Fprintf(w, "\nSend these %d report(s) to %s? [y/N] ", len(gs), feedback.Repo)
		ans, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			fmt.Fprintln(w, "Nothing sent.")
			return nil
		}
	}
	gh := ghRunner()
	if gh == nil {
		fmt.Fprintln(w, "\nThe GitHub CLI (gh) is not installed or not signed in, so open each link, review it and submit it:")
		for _, g := range gs {
			fmt.Fprintf(w, "\n%s\n%s\n", g.Title(), g.IssueURL())
			st.MarkSent(g, "link")
		}
		return feedback.SaveState(e.Private(), st)
	}
	res, err := feedback.Submit(gh, gs)
	for i, r := range res {
		st.MarkSent(gs[i], r.URL)
	}
	if serr := feedback.SaveState(e.Private(), st); serr != nil && err == nil {
		err = serr
	}
	if asJSON {
		if jerr := printJSON(w, map[string]any{"results": res}); jerr != nil {
			return jerr
		}
	} else {
		fmt.Fprintln(w)
		for _, r := range res {
			verb := "Filed"
			if r.Action == "commented" {
				verb = "Added to the open report"
			}
			fmt.Fprintf(w, "%s: [%s] %s %s\n", verb, r.Kind, redact.Line(r.Subject), r.URL)
		}
		if len(res) > 0 {
			fmt.Fprintln(w, "Thank you. Fixed rules ship in the next release.")
		}
	}
	if err != nil {
		return errors.New("sending stopped: " + err.Error())
	}
	return nil
}

func printPending(w io.Writer, gs []feedback.Group) {
	if len(gs) == 0 {
		fmt.Fprintln(w, "No reports waiting: no closed false positives or confirmed missed issues that were not reported yet.")
		return
	}
	fmt.Fprintf(w, "Reports not sent yet (%d):\n", len(gs))
	for _, g := range gs {
		ids := g.Findings
		if len(ids) > 5 {
			ids = append(ids[:5:5], fmt.Sprintf("and %d more", len(g.Findings)-5))
		}
		noun := "findings"
		if g.Count == 1 {
			noun = "finding"
		}
		fmt.Fprintf(w, "  %-50s %3d %-8s %-16s %s\n", g.Title(), g.Count, noun, g.FileType, strings.Join(ids, ", "))
	}
}

// feedbackHint says, after triage, when reports for the project are ready,
// unless the user turned feedback off.
func feedbackHint(e *engine.Engine, w io.Writer) {
	st, gs, err := e.PendingFeedback()
	if err != nil || len(gs) == 0 || st.Mode == feedback.ModeOff {
		return
	}
	fmt.Fprintf(w, "%d report(s) about wrong or missed findings can go to the PandaWard project: pandaward feedback pending\n", len(gs))
}
