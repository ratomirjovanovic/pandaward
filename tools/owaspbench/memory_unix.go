//go:build unix

package main

import (
	"os"
	"runtime"
	"syscall"
)

// maxRSSMiB reads the peak resident set from the child's resource usage.
// Linux reports kibibytes, macOS bytes.
func maxRSSMiB(ps *os.ProcessState) float64 {
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return float64(ru.Maxrss) / (1 << 20)
	}
	return float64(ru.Maxrss) / 1024
}
