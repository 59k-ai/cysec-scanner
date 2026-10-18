// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package governance

import (
	"os"
	"sort"
	"strings"
	"testing"

	scannerdata "github.com/cysec-watch/cysec-scanner"
)

// noticesPath is the repo-root THIRD_PARTY_NOTICES.md relative to this test
// package's working directory (go test runs with CWD = the package dir).
const noticesPath = "../../THIRD_PARTY_NOTICES.md"

// dataset is one logical bundled dataset derived from data/allowlist.json. A
// dataset may be backed by several allowlist entries (the IEEE OUI snapshot is
// three files: MA-L/MA-M/MA-S) — grouping them here is what lets the test prove
// that entries sharing a license are still each represented (no dedup drops a
// required attribution).
type dataset struct {
	name     string   // human label used only in failure messages
	minPath  string   // smallest embedded data path — the deterministic sort key
	order    string   // a string that must appear in its own notices section (order probe)
	required []string // markers that MUST appear in THIRD_PARTY_NOTICES.md
}

// TestNoticesComplete is the LIC-01 completeness gate. It parses the allowlist
// (the single source of truth), groups entries into logical datasets, and
// asserts THIRD_PARTY_NOTICES.md:
//   - carries a notice marker for every distinct dataset license/source,
//   - lists each dataset separately even when two share a license (no dedup
//     silently drops a required attribution — probed via the three OUI blocks
//     which all share the NOASSERTION license),
//   - states the empty Go-dependency case explicitly, and
//   - emits datasets in deterministic order sorted by embedded data path.
func TestNoticesComplete(t *testing.T) {
	t.Parallel()

	manifest, err := LoadAllowlist(scannerdata.DataFS)
	if err != nil {
		t.Fatalf("LoadAllowlist(scannerdata.DataFS) = %v, want nil", err)
	}

	b, err := os.ReadFile(noticesPath)
	if err != nil {
		t.Fatalf("read %q: %v", noticesPath, err)
	}
	notices := string(b)

	// Group allowlist entries into logical datasets.
	oui := dataset{name: "IEEE OUI", order: "IEEE OUI"}
	byName := map[string]*dataset{}
	var order []*dataset

	for _, e := range manifest {
		switch {
		case strings.HasPrefix(e.Path, "data/oui/"):
			if oui.minPath == "" {
				oui.minPath = e.Path
				oui.required = append(oui.required, "does not assert any copyright")
				byName[oui.name] = &oui
				order = append(order, &oui)
			} else if e.Path < oui.minPath {
				oui.minPath = e.Path
			}
			// No-dedup probe: every registry block that shares the NOASSERTION
			// license MUST be named in the notices — proving none was dropped.
			if e.RegistryBlock == "" {
				t.Errorf("OUI allowlist entry %q missing registry_block", e.Path)
			}
			oui.required = append(oui.required, e.RegistryBlock)
		default:
			// A licensed dataset with a retain-notice copyright (e.g. Recog BSD-2).
			ds, ok := byName[e.License]
			if !ok {
				ds = &dataset{
					name:    e.License + " dataset",
					minPath: e.Path,
					order:   e.License,
				}
				if e.Copyright != "" {
					// Attribution token (e.g. "Rapid7") must be retained verbatim.
					ds.required = append(ds.required, e.Copyright)
					ds.order = firstCopyrightHolder(e.Copyright)
				}
				ds.required = append(ds.required, e.License)
				byName[e.License] = ds
				order = append(order, ds)
			} else {
				if e.Path < ds.minPath {
					ds.minPath = e.Path
				}
				if e.Copyright != "" {
					ds.required = append(ds.required, e.Copyright)
				}
			}
		}
	}

	// Every required marker for every dataset must be present.
	for _, ds := range order {
		for _, marker := range ds.required {
			if !strings.Contains(notices, marker) {
				t.Errorf("THIRD_PARTY_NOTICES.md missing marker %q for dataset %s", marker, ds.name)
			}
		}
	}

	// Empty Go-dependency case stated explicitly (LIC-01 empty probe).
	if !strings.Contains(strings.ToLower(notices), "no third-party go runtime dependencies") {
		t.Error("THIRD_PARTY_NOTICES.md must explicitly state the empty Go-dependency case")
	}

	// Deterministic order: datasets must appear sorted by embedded data path.
	sort.Slice(order, func(i, j int) bool { return order[i].minPath < order[j].minPath })
	prev := -1
	for _, ds := range order {
		idx := strings.Index(notices, ds.order)
		if idx < 0 {
			t.Errorf("dataset %s order-marker %q not found in notices", ds.name, ds.order)
			continue
		}
		if idx < prev {
			t.Errorf("dataset %s (path %s) appears out of deterministic (path-sorted) order", ds.name, ds.minPath)
		}
		prev = idx
	}
}

// firstCopyrightHolder extracts a stable attribution token from a copyright
// string like "Copyright (c) 2014-2015, Rapid7" → "Rapid7", used only as the
// per-dataset order probe.
func firstCopyrightHolder(c string) string {
	if i := strings.LastIndex(c, ", "); i >= 0 {
		return strings.TrimSpace(c[i+2:])
	}
	return c
}
