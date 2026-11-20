//go:build !unix

package main

import "os"

// maxRSSMiB has no figure where the platform exposes no peak resident set
// through the standard library.
func maxRSSMiB(*os.ProcessState) float64 { return 0 }
