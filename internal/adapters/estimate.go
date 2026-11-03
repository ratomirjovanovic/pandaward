package adapters

import (
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

// Estimate guesses how long an adapter will run on c.Inv. It only weights
// the scan progress of a project that has no recorded runs yet; later scans
// use the durations in the ledger. The rates come from scans of real
// TypeScript projects (semgrep 1.182 took 20 to 40 seconds per MB of code)
// and are deliberately rough.
func Estimate(a Adapter, c *Context) time.Duration {
	if t, ok := a.(*externalTool); ok {
		// These end at once with BLOCKED.
		if _, err := t.Lookup(); err != nil {
			return 0
		}
		if t.network && !c.Cfg.Scan.AllowToolNetwork {
			return 0
		}
	}
	var code, all float64 // MB
	if c.Inv != nil {
		for _, f := range c.Inv.Files {
			all += float64(f.Size)
			if inventory.CodeLangs[f.Lang] {
				code += float64(f.Size)
			}
		}
	}
	code, all = code/(1<<20), all/(1<<20)
	per := func(base, rate time.Duration, mb float64) time.Duration {
		return base + time.Duration(float64(rate)*mb)
	}
	switch a.Name() {
	case "semgrep":
		return per(15*time.Second, 30*time.Second, code)
	case "gitleaks":
		return per(5*time.Second, 2*time.Second, all)
	case "trivy":
		return per(15*time.Second, time.Second, all)
	case "osv-scanner":
		return 5 * time.Second
	case "apktool", "mobsf":
		return 30 * time.Second
	case "builtin-code":
		return per(time.Second, time.Second, code)
	case "builtin-secrets":
		return per(time.Second, 300*time.Millisecond, all)
	}
	return time.Second
}
