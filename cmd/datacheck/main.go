// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Command datacheck is the standalone data-governance verifier. It enforces two
// gates and exits non-zero if either is violated (the exit-code-as-contract the
// GitHub Actions governance job relies on):
//
//  1. Denylist — scans the SHIPPED-DATA subtree (<root>/data) only for
//     contaminating (copyleft/OEM) datasets. The repo's deliberately-
//     contaminating testdata/fixtures/* live OUTSIDE data/ and are never
//     scanned, so a clean checkout passes.
//  2. Allowlist integrity — two-way SHA-256 match of the embedded data FS
//     (scannerdata.DataFS) against data/allowlist.json.
//
// Usage:
//
//	datacheck --root <dir>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	scannerdata "github.com/cysec-watch/cysec-scanner"
	"github.com/cysec-watch/cysec-scanner/internal/governance"
)

func main() {
	root := flag.String("root", ".", "repository root to scan (the denylist scans <root>/data only)")
	flag.Parse()

	os.Exit(run(*root, os.Stdout, os.Stderr))
}

// run performs both gates and returns the process exit code: 0 clean,
// non-zero on any violation or error.
func run(root string, stdout, stderr *os.File) int {
	violations := 0

	// Gate 1 — denylist over the shipped-data subtree only.
	dataRoot := filepath.Join(root, "data")
	denyViolations, err := governance.ScanForContaminatingData(dataRoot)
	if err != nil {
		fmt.Fprintf(stderr, "datacheck: denylist scan failed: %v\n", err)
		return 2
	}
	for _, v := range denyViolations {
		fmt.Fprintf(stderr, "DENYLIST VIOLATION: %s\n", v.String())
		violations++
	}

	// Gate 2 — allowlist integrity over the embedded FS the binary ships.
	if err := governance.VerifyEmbeddedData(scannerdata.DataFS); err != nil {
		fmt.Fprintf(stderr, "ALLOWLIST VIOLATION: %v\n", err)
		violations++
	}

	if violations > 0 {
		fmt.Fprintf(stderr, "datacheck: FAILED with %d violation(s)\n", violations)
		return 1
	}
	fmt.Fprintf(stdout, "datacheck: OK (denylist + allowlist integrity clean for root %q)\n", root)
	return 0
}
