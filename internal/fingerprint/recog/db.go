// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package recog is an original-Go matcher over a vendored, license-clean service
// fingerprint database (the Recog XML format). It compiles each fingerprint's
// pattern with the standard library's RE2 engine and matches a captured banner
// against them, returning the structured service identity (product, version,
// CPE) plus any OS cue the matched fingerprint carries.
//
// The matcher adds no module dependency beyond the standard library
// (encoding/xml + regexp). RE2 is used deliberately: it guarantees linear-time
// matching, so a hostile banner can never trigger catastrophic backtracking
// (never-raises, bounded discipline). Any pattern the RE2 engine cannot compile
// is skipped and counted at load time rather than crashing the database — a
// fingerprint authored for a backtracking dialect degrades gracefully to a miss.
package recog

import (
	"encoding/xml"
	"io/fs"
	"regexp"
	"strconv"
)

// xmlFingerprints is the root <fingerprints> element of a Recog database file.
// Only the attributes this matcher consumes are decoded.
type xmlFingerprints struct {
	Matches      string           `xml:"matches,attr"`
	Protocol     string           `xml:"protocol,attr"`
	DatabaseType string           `xml:"database_type,attr"`
	Preference   string           `xml:"preference,attr"`
	Fingerprints []xmlFingerprint `xml:"fingerprint"`
}

// xmlFingerprint is one <fingerprint> entry: a match pattern, an ordered param
// table, and optional golden <example> strings used by the database self-tests.
type xmlFingerprint struct {
	Pattern     string       `xml:"pattern,attr"`
	Description string       `xml:"description"`
	Examples    []xmlExample `xml:"example"`
	Params      []xmlParam   `xml:"param"`
}

// xmlExample is a golden sample banner (element text) with the param values it is
// expected to yield (as attributes keyed by param name, e.g. service.version).
type xmlExample struct {
	Text  string     `xml:",chardata"`
	Attrs []xml.Attr `xml:",any,attr"`
}

// xmlParam is one <param>: a static value (value set) is used verbatim; an empty
// value takes the regexp capture group at Pos.
type xmlParam struct {
	Pos   int    `xml:"pos,attr"`
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// compiled is a fingerprint whose pattern successfully compiled under RE2.
type compiled struct {
	re       *regexp.Regexp
	params   []xmlParam
	examples []xmlExample
}

// DB is a loaded, compiled fingerprint database ready to match banners. It is
// read-only after Load.
type DB struct {
	matches    string
	protocol   string
	preference float64
	compiled   []compiled
	dropped    int
	total      int
}

// defaultPreference is the match confidence used when the database declares no
// preference attribute. A structured banner match is a high-fidelity signal.
const defaultPreference = 0.9

// Load reads and parses the Recog XML at path from fsys (the embedded governed
// data FS), compiling every fingerprint pattern under RE2. A pattern RE2 rejects
// is skipped and counted (see Dropped) — Load never fails on an individual
// incompatible pattern. Load returns an error only when the file cannot be read
// or is not well-formed XML.
func Load(fsys fs.FS, path string) (*DB, error) {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, err
	}
	var root xmlFingerprints
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	db := &DB{
		matches:    root.Matches,
		protocol:   root.Protocol,
		preference: parsePreference(root.Preference),
		total:      len(root.Fingerprints),
	}
	// Preserve declaration order so first-match-wins is stable across runs.
	for _, fp := range root.Fingerprints {
		re, err := regexp.Compile(fp.Pattern)
		if err != nil {
			db.dropped++
			continue
		}
		db.compiled = append(db.compiled, compiled{
			re:       re,
			params:   fp.Params,
			examples: fp.Examples,
		})
	}
	return db, nil
}

// parsePreference converts a Recog preference attribute to a confidence in
// [0,1], falling back to defaultPreference for an empty or out-of-range value.
func parsePreference(s string) float64 {
	if s == "" {
		return defaultPreference
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 || v > 1 {
		return defaultPreference
	}
	return v
}

// Dropped reports how many fingerprints were skipped because their pattern did
// not compile under RE2. The database-corpus self-test asserts this stays at or
// below a documented ceiling.
func (db *DB) Dropped() int { return db.dropped }

// Total reports the number of fingerprints declared in the source database
// (including any dropped at compile time).
func (db *DB) Total() int { return db.total }

// Protocol reports the database's declared protocol (e.g. "ssh").
func (db *DB) Protocol() string { return db.protocol }
