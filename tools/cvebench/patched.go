package main

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
)

var hunkRe = regexp.MustCompile(`(?m)^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// parseHunks returns the line ranges of the new file that a zero-context diff
// adds or changes. A hunk that only deletes lines becomes the single line where
// the deletion happened.
func parseHunks(diff string) [][2]int {
	var out [][2]int
	for _, m := range hunkRe.FindAllStringSubmatch(diff, -1) {
		start, _ := strconv.Atoi(m[1])
		n := 1
		if m[2] != "" {
			n, _ = strconv.Atoi(m[2])
		}
		if n == 0 {
			out = append(out, [2]int{start, start})
			continue
		}
		out = append(out, [2]int{start, start + n - 1})
	}
	return out
}

// PatchedRanges maps every file that held a labelled weakness to the line
// ranges of the post-patch file that the fix added or changed. It diffs the two
// checkouts without any history, so it works on the depth-1 checkouts the
// benchmark uses. A file it cannot diff is left out.
func PatchedRanges(ctx context.Context, preDir, postDir string, c CVE) map[string][][2]int {
	out := map[string][][2]int{}
	for _, w := range c.PrePatch.Weaknesses {
		file := cleanPath(w.Location.File)
		if _, done := out[file]; done {
			continue
		}
		// git diff --no-index exits 1 when the files differ, which is the case we want.
		text, _ := git(ctx, preDir, "diff", "--no-index", "--no-color", "--unified=0", "--", filepath.FromSlash(file), filepath.Join(postDir, filepath.FromSlash(file)))
		out[file] = parseHunks(text)
	}
	return out
}

// touches reports whether a finding's lines meet a patched range, with one
// line of margin on each side.
func touches(ranges [][2]int, line, end int) bool {
	if end < line {
		end = line
	}
	for _, r := range ranges {
		if line <= r[1]+1 && r[0]-1 <= end {
			return true
		}
	}
	return false
}
