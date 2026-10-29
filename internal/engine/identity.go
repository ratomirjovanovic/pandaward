package engine

import (
	"sort"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// signalBase is the identity of a signal without its occurrence number.
func signalBase(s model.Signal) string {
	return s.RuleID + "|" + s.File + "|" + s.Key + "|" + normalizeSnippet(s.Snippet)
}

// fileView is what assignFingerprints needs to know about files.
type fileView struct {
	exists func(path string) bool
	// sameContent reports whether newPath now has the content oldPath had
	// in assessment asmt.
	sameContent func(asmt, oldPath, newPath string) bool
}

// assignment links the signals of one scan to ledger findings.
type assignment struct {
	FP    []string              // fingerprint per signal
	Moved map[int]model.Finding // signal index -> finding it continues from another file
}

// assignFingerprints gives each signal the fingerprint of the ledger finding
// it continues, so a retest never trades one finding's identity for another's.
//
// Signals that share a base (identical hits of one rule in one file) are
// aligned with that base's findings in line order, minimizing how far each
// one moved, rather than matched by occurrence number: fixing the first of
// two identical hits remediates the first finding, not the second, and lines
// inserted above both keep each finding on its own hit. A signal with no
// finding of its own continues an unmatched finding of the same collector,
// rule, key and snippet whose file is gone, so a moved or renamed file keeps
// its finding IDs and triage instead of reading as a fix plus new findings.
// A collector that reports no snippet gives no proof the code is the same,
// so then the new file must have the exact content the old one had when the
// finding was last observed.
func assignFingerprints(signals []model.Signal, ledger []model.Finding, fv fileView) assignment {
	byFP := map[string]model.Finding{}
	perFile := map[string]int{} // rule|file -> findings in the ledger
	for _, f := range ledger {
		byFP[f.Fingerprint] = f
		perFile[f.RuleID+"|"+f.File]++
	}
	groups := map[string][]int{}
	var order []string
	for i, s := range signals {
		b := signalBase(s)
		if _, ok := groups[b]; !ok {
			order = append(order, b)
		}
		groups[b] = append(groups[b], i)
	}
	a := assignment{FP: make([]string, len(signals)), Moved: map[int]model.Finding{}}
	used := map[string]bool{}
	var fresh []int
	for _, b := range order {
		idx := groups[b]
		s0 := signals[idx[0]]
		var tracked, fixed []model.Finding
		for k := 1; k <= len(idx)+perFile[s0.RuleID+"|"+s0.File]; k++ {
			if f, ok := byFP[fingerprint(b, k)]; ok {
				if f.Status == model.FindingRemediated {
					fixed = append(fixed, f)
				} else {
					tracked = append(tracked, f)
				}
			}
		}
		// Findings still tracked first; what is left over can only be a
		// regression of a remediated one.
		rest := align(signals, idx, tracked, a.FP, used)
		rest = align(signals, rest, fixed, a.FP, used)
		for _, si := range rest {
			for k := 1; ; k++ {
				fp := fingerprint(b, k)
				if _, exists := byFP[fp]; !exists && !used[fp] {
					a.FP[si], used[fp] = fp, true
					break
				}
			}
			fresh = append(fresh, si)
		}
	}

	// Moves: a fresh signal continues a finding that was not matched, is not
	// remediated, came from the same collector and rule, and whose file no
	// longer exists, provided the finding's own fingerprint proves it had the
	// same key and snippet.
	claimed := map[string]bool{}
	for _, fp := range a.FP {
		claimed[fp] = true
	}
	movedTo := map[string][]int{} // new base -> fresh signals
	var bases []string
	for _, si := range fresh {
		b := signalBase(signals[si])
		if _, ok := movedTo[b]; !ok {
			bases = append(bases, b)
		}
		movedTo[b] = append(movedTo[b], si)
	}
	for _, b := range bases {
		idx := movedTo[b]
		s := signals[idx[0]]
		snip := normalizeSnippet(s.Snippet)
		gone := map[string][]model.Finding{} // old file -> candidates
		var files []string
		for _, f := range ledger {
			if claimed[f.Fingerprint] || f.Status == model.FindingRemediated || f.Collector != s.Collector || f.RuleID != s.RuleID || f.File == s.File || fv.exists(f.File) {
				continue
			}
			if !sameBase(f, s.RuleID+"|"+f.File+"|"+s.Key+"|"+snip, perFile[f.RuleID+"|"+f.File]) {
				continue
			}
			if snip == "" && !fv.sameContent(f.AssessmentID, f.File, s.File) {
				continue
			}
			if _, ok := gone[f.File]; !ok {
				files = append(files, f.File)
			}
			gone[f.File] = append(gone[f.File], f)
		}
		// The old file with the most matching findings is the likeliest
		// source; ties go to the first name.
		sort.SliceStable(files, func(i, j int) bool {
			if len(gone[files[i]]) != len(gone[files[j]]) {
				return len(gone[files[i]]) > len(gone[files[j]])
			}
			return files[i] < files[j]
		})
		rest := idx
		for _, file := range files {
			if len(rest) == 0 {
				break
			}
			cands := gone[file]
			sort.SliceStable(cands, func(i, j int) bool { return cands[i].StartLine < cands[j].StartLine })
			sigs := append([]int(nil), rest...)
			sort.SliceStable(sigs, func(i, j int) bool { return signals[sigs[i]].StartLine < signals[sigs[j]].StartLine })
			match := alignLines(lines(signals, sigs), findingLines(cands))
			rest = rest[:0:0]
			for i, si := range sigs {
				if m := match[i]; m >= 0 {
					a.Moved[si] = cands[m]
					claimed[cands[m].Fingerprint] = true
				} else {
					rest = append(rest, si)
				}
			}
		}
	}
	return a
}

// align matches signals idx to findings fs in line order and records the
// matched fingerprints. It returns the signals left unmatched, in input order.
func align(signals []model.Signal, idx []int, fs []model.Finding, fp []string, used map[string]bool) []int {
	if len(idx) == 0 || len(fs) == 0 {
		return idx
	}
	fs = append([]model.Finding(nil), fs...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].StartLine < fs[j].StartLine })
	sigs := append([]int(nil), idx...)
	sort.SliceStable(sigs, func(i, j int) bool { return signals[sigs[i]].StartLine < signals[sigs[j]].StartLine })
	match := alignLines(lines(signals, sigs), findingLines(fs))
	unmatched := map[int]bool{}
	for i, si := range sigs {
		if m := match[i]; m >= 0 {
			fp[si], used[fs[m].Fingerprint] = fs[m].Fingerprint, true
		} else {
			unmatched[si] = true
		}
	}
	var rest []int
	for _, si := range idx {
		if unmatched[si] {
			rest = append(rest, si)
		}
	}
	return rest
}

func lines(signals []model.Signal, idx []int) []int {
	out := make([]int, len(idx))
	for i, si := range idx {
		out[i] = signals[si].StartLine
	}
	return out
}

func findingLines(fs []model.Finding) []int {
	out := make([]int, len(fs))
	for i, f := range fs {
		out[i] = f.StartLine
	}
	return out
}

// alignLines pairs sorted lines a with sorted lines b without crossing,
// matching min(len(a), len(b)) pairs with the smallest total distance. It
// returns, for each element of a, the index in b it is paired with or -1.
// Order is kept because code edits shift identical hits together; they do
// not reorder them.
func alignLines(a, b []int) []int {
	n, m := len(a), len(b)
	swap := n > m
	if swap {
		a, b, n, m = b, a, m, n
	}
	// cost[i][j]: best total distance pairing a[i:] with b[j:], every a used.
	const inf = int(^uint(0) >> 2)
	cost := make([][]int, n+1)
	for i := range cost {
		cost[i] = make([]int, m+1)
		for j := range cost[i] {
			if i < n {
				cost[i][j] = inf
			}
		}
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - (n - i); j >= 0; j-- {
			d := a[i] - b[j]
			if d < 0 {
				d = -d
			}
			best := d + cost[i+1][j+1]
			if skip := cost[i][j+1]; skip < best {
				best = skip
			}
			cost[i][j] = best
		}
	}
	pair := make([]int, n)
	for i, j := 0, 0; i < n; j++ {
		d := a[i] - b[j]
		if d < 0 {
			d = -d
		}
		if cost[i][j] == d+cost[i+1][j+1] {
			pair[i] = j
			i++
		}
	}
	if !swap {
		return pair
	}
	out := make([]int, m)
	for i := range out {
		out[i] = -1
	}
	for i, j := range pair {
		out[j] = i
	}
	return out
}

// sameBase reports whether finding f was fingerprinted from base.
func sameBase(f model.Finding, base string, n int) bool {
	for k := 1; k <= n; k++ {
		if fingerprint(base, k) == f.Fingerprint {
			return true
		}
	}
	return false
}
