package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
)

// cmdVerifyReport compares the control claims of a report with the ledger. It
// exits 1 when the report contains false assurance, so it can gate a CI step or
// a hook. A report that is only more cautious than the ledger exits 0.
func cmdVerifyReport(args []string, stdin io.Reader, w io.Writer) error {
	fs, root := newFS("verify-report")
	asJSON := fs.Bool("json", false, "JSON output")
	complete := fs.Bool("complete", false, "the report is a full review: it may not leave out an open finding (FAIL or SUSPECTED)")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	var text []byte
	switch {
	case len(rest) == 0 || (len(rest) == 1 && rest[0] == "-"):
		text, err = io.ReadAll(io.LimitReader(stdin, 4<<20))
	case len(rest) == 1:
		text, err = os.ReadFile(rest[0])
	default:
		return exitErr{2, "usage: pandaward verify-report [--complete] [--json] [FILE|-]"}
	}
	if err != nil {
		return exitErr{2, err.Error()}
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	res, err := e.VerifyReport(string(text), *complete)
	if err != nil {
		return exitErr{2, err.Error()}
	}
	if *asJSON {
		if err := printJSON(w, res); err != nil {
			return err
		}
	} else {
		printVerify(w, res)
	}
	if res.Unsupported {
		return exitErr{1, "the report is not supported by the ledger"}
	}
	return nil
}

func printVerify(w io.Writer, r *engine.VerifyResult) {
	fmt.Fprintf(w, "Checked %d control claim(s) against %s.\n", r.Claims, r.Assessment)
	if r.Note != "" {
		fmt.Fprintln(w, "Note: "+r.Note)
	}
	if len(r.Mismatches) == 0 {
		fmt.Fprintln(w, "OK: nothing in the report is contradicted by the ledger. Only structured lines and all-clear statements are read.")
		return
	}
	for _, m := range r.Mismatches {
		tag := "note"
		if m.FalseAssurance {
			tag = "FALSE ASSURANCE"
		}
		ctrl := m.Control
		if ctrl == "" {
			ctrl = "report"
		}
		fmt.Fprintf(w, "  %s  %s  %s: %s\n", tag, ctrl, m.Kind, m.Detail)
	}
	if r.Unsupported {
		fmt.Fprintln(w, "The report says more than the ledger supports. Correct it before relying on it.")
	} else {
		fmt.Fprintln(w, "OK: the report is more careful than the ledger, which is never blocked.")
	}
}
