// Package oui resolves a MAC address to its registered organisation using the
// embedded IEEE registry snapshot.
//
// IEEE assigns MAC-address space in three block sizes whose prefixes differ in
// length: MA-L (24-bit, 6 hex digits), MA-M (28-bit, 7 hex digits) and MA-S
// (36-bit, 9 hex digits). MA-M and MA-S assignments are carved out of MA-L
// space, so a lookup that only inspected the first 24 bits would mis-attribute a
// fine-grained assignment to the registry holder of the enclosing block. This
// package therefore matches the LONGEST registered prefix first (9 -> 7 -> 6
// hex) and treats that most-specific assignment as authoritative.
//
// Two values are deliberately non-answers, yielding a nil vendor rather than a
// misleading label:
//   - an Organization Name of "Private" (case-insensitive): IEEE redacts some
//     registrations, and surfacing the literal "Private" — or falling through to
//     the parent block's registry holder — would present a non-vendor as if it
//     were the device maker;
//   - an empty Organization Name.
//
// All data is read from the compile-time embedded snapshot; the package adds no
// module dependency beyond the standard library.
package oui

import (
	"encoding/csv"
	"strings"
	"sync"

	scannerdata "github.com/cysec-watch/cysec-scanner"
)

// Embedded CSV paths for the three IEEE registry blocks. Each file shares the
// header "Registry,Assignment,Organization Name,Organization Address".
const (
	pathMAL = "data/oui/oui.csv"   // MA-L, 24-bit / 6 hex
	pathMAM = "data/oui/mam.csv"   // MA-M, 28-bit / 7 hex
	pathMAS = "data/oui/oui36.csv" // MA-S, 36-bit / 9 hex
)

// prefixOrder is the longest-prefix probe order: 36-bit, 28-bit, then 24-bit.
var prefixOrder = []int{9, 7, 6}

var (
	loadOnce sync.Once
	// tables maps a hex-prefix length (9/7/6) to its {assignment-prefix:
	// organisation} map. Built once, read-only thereafter.
	tables map[int]map[string]string
)

// load parses the three embedded registry blocks into prefix maps exactly once.
// A missing or malformed block degrades to an empty map for that length rather
// than panicking — an absent OUI signal must resolve to a nil vendor, never a
// crash.
func load() {
	tables = map[int]map[string]string{9: {}, 7: {}, 6: {}}
	loadBlock(pathMAL, 6)
	loadBlock(pathMAM, 7)
	loadBlock(pathMAS, 9)
}

// loadBlock reads one registry CSV into tables[wantLen]. It skips the header row
// and tolerates ragged rows (FieldsPerRecord = -1). Any read/parse failure
// leaves the (already-initialised, possibly empty) map in place.
func loadBlock(path string, wantLen int) {
	f, err := scannerdata.DataFS.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return
	}
	m := tables[wantLen]
	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue // header or short row
		}
		assign := strings.ToUpper(strings.TrimSpace(row[1]))
		org := strings.TrimSpace(row[2])
		if len(assign) != wantLen || org == "" {
			continue
		}
		m[assign] = org
	}
}

// normalizeHex strips every non-hex character from s and upper-cases the rest,
// so colon-, hyphen- and dot-separated or bare-hex MAC forms normalise alike.
func normalizeHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - ('a' - 'A'))
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LookupVendor returns the registered organisation for mac, or nil when no
// vendor can be honestly reported. It normalises mac to upper-case hex, requires
// at least 24 bits (6 hex digits), then probes the longest registered prefix
// first (MA-S 36-bit, MA-M 28-bit, MA-L 24-bit). The first registered prefix
// found is authoritative: a "Private" or empty organisation at that length
// resolves to nil rather than falling through to a less-specific block.
func LookupVendor(mac string) *string {
	loadOnce.Do(load)

	h := normalizeHex(mac)
	if len(h) < 6 {
		return nil
	}
	for _, n := range prefixOrder {
		if len(h) < n {
			continue
		}
		org, ok := tables[n][h[:n]]
		if !ok {
			continue
		}
		// Longest registered prefix is authoritative.
		if org == "" || strings.EqualFold(org, "Private") {
			return nil
		}
		out := org
		return &out
	}
	return nil
}
