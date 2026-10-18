// Package scannerdata embeds the governed data tree (datasets + the allowlist
// manifest) into the binary at compile time.
//
// This file MUST live at the module root. A //go:embed directive only matches
// files at or below the directory of the declaring source file and rejects
// ".." path elements, and data/ is a direct subdirectory of the module root.
// An embed declared in internal/governance referencing "data" (or "../../data")
// fails to compile with "pattern data: no matching files found". The governance
// package therefore imports this package and operates on DataFS.
package scannerdata

import "embed"

// DataFS is the read-only, compile-time snapshot of the data/ tree. Because
// go:embed fixes contents at compile time, any file present in data/ at build
// time is already in the shipped binary — the allowlist integrity test
// (internal/governance.VerifyEmbeddedData) is what refuses an unlisted file,
// and it must run as a CI/test gate, not merely at runtime.
//
//go:embed data
var DataFS embed.FS
