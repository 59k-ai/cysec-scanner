// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package governance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// Violation records one denylist hit: the offending file, a human-readable
// reason, which contaminating dataset signature matched, and which detection
// layer caught it (filename / content / hash).
type Violation struct {
	Path    string // path to the offending file (as walked)
	Reason  string // why it was flagged
	Dataset string // the contaminating dataset it matched (e.g. "nmap-service-probes")
	Layer   string // detection layer that caught it: "filename", "content", or "hash"
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s (dataset: %s, layer: %s)", v.Path, v.Reason, v.Dataset, v.Layer)
}

// LICENSE BASIS — every entry below is a copyleft / OEM-restricted / patent-
// pending dataset that MUST NOT reach the published Apache-2.0 engine
// (01-RESEARCH.md §"Denylisted datasets — license basis"):
//
//   nmap-service-probes, nmap-os-db  NPSL (GPLv2-based + extra terms; data files
//                                    named as derivative-work triggers; OEM
//                                    license sold separately). Copyleft.
//   p0f.fp                           GPL-2.0-or-later / LGPL-2.1 (both copyleft).
//   manuf (Wireshark)                GPL-2.0. Use the IEEE OUI primary source
//                                    (public-domain-declared) instead — manuf is
//                                    OUI-derived but SHIPPED by Wireshark under
//                                    GPL, mixing in Ethereal/Patton rows
//                                    (RESEARCH Pitfall 5).
//   JA4+ server (JA4S/JA4H/JA4X/...)  FoxIO-License-1.1, "all JA4+ methods are
//                                    patent pending", monetization-restricted,
//                                    OEM license required.
//   Npcap                            OEM-paid, no free redistribution (also
//                                    forces cgo, breaking CGO_ENABLED=0).
//
// NOT DENYLISTED — JARM: JARM (salesforce/jarm) is BSD-3-Clause with NO patent
// grant and NO asserted/pending patent, so it is permissive and allowlist-
// eligible (RESEARCH §"JARM — ALLOWLIST", Pitfall 3). It must stay OFF this
// denylist. Its look-alike JA4+ server (FoxIO-License-1.1, patent-pending) IS a
// target above. JARM and JA4+ are both TLS fingerprinting and the names rhyme,
// but they are legally OPPOSITE — never collapse them into a generic "TLS
// fingerprinting" entry; name JA4+ specifically and keep JARM clear.

// denylistedBasenames is FILENAME layer (layer 1), exact-basename fast path.
var denylistedBasenames = map[string]string{
	"nmap-service-probes": "nmap-service-probes",
	"nmap-os-db":          "nmap-os-db",
	"p0f.fp":              "p0f.fp",
	"manuf":               "manuf (Wireshark)",
}

// denylistedGlobs is the FILENAME layer (layer 1) glob branch: filepath.Match
// patterns applied to the basename, for datasets whose files vary in suffix or
// embedding (manuf.*, ja4*_server*, *npcap*, *.npl).
var denylistedGlobs = []struct{ pattern, dataset string }{
	{"manuf.*", "manuf (Wireshark)"},
	{"ja4*_server*", "JA4+ server"},
	{"*npcap*", "Npcap"},
	{"*.npl", "Npcap"},
}

// contentSignatures is the CONTENT-SIGNATURE layer (layer 2): per-line regexes
// that catch a RENAMED contaminating file whose basename was changed to evade
// the filename layer. A slice (not a map) keeps match order deterministic.
//
// Each signature is a format no permissive dataset in this repo uses — verified
// against the vendored Recog XML (indented XML, matches none) and the IEEE OUI
// CSV adjacency control (comma-separated, matches none). The manuf signature is
// deliberately TAB-anchored so it can NOT match the comma-separated IEEE OUI CSV
// (TestDenylistPassesAllowlistedFormats proves this — RESEARCH Pitfall 5 / T-1-06).
var contentSignatures = []struct {
	dataset string
	re      *regexp.Regexp
}{
	// nmap-service-probes directive lines.
	{"nmap-service-probes", regexp.MustCompile(`^(Probe|match|softmatch|ports|Exclude) `)},
	// nmap-os-db fingerprint records.
	{"nmap-os-db", regexp.MustCompile(`^Fingerprint `)},
	{"nmap-os-db", regexp.MustCompile(`^SEQ\(`)},
	// p0f.fp section headers + signature lines.
	{"p0f.fp", regexp.MustCompile(`^\[(tcp|http|mtu)(:[a-z]+)?\]`)},
	{"p0f.fp", regexp.MustCompile(`^sig\s*=`)},
	// Wireshark manuf: TAB-separated MAC OUI prefix (distinct from CSV).
	{"manuf (Wireshark)", regexp.MustCompile(`^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\t`)},
	// JA4+ JA4S server-hash token (e.g. t130200_1301_234ea6891581) + header marker.
	{"JA4+ server", regexp.MustCompile(`^[qt][0-9]{6}_[0-9a-f]{4}_[0-9a-f]{12}`)},
	{"JA4+ server", regexp.MustCompile(`(?i)^ja4s\b`)},
	// Npcap EULA / license header markers.
	{"Npcap", regexp.MustCompile(`(?i)npcap.*(license|eula|copyright|end user)`)},
}

// KnownHashBlocklist is the KNOWN-HASH layer (layer 3): SHA-256 (lowercase hex)
// of an exact contaminating file → its dataset name. This is the strongest
// layer for an EXACT upstream copy: it catches the file regardless of basename
// AND regardless of whether its content trips a signature regex.
//
// Seeded with the SHA-256 of each committed contaminating fixture under
// testdata/fixtures/*, so an exact copy of any of them is caught even if renamed
// to a neutral basename. The last entry is an opaque blob that trips NO content
// signature — it exists so the hash layer can be proven in isolation
// (TestDenylistKnownHashLayer).
//
// SCAN-SCOPE NOTE (01-01): seeding these testdata-fixture hashes does NOT redden
// the production `datacheck --root .` run — datacheck scopes its denylist scan to
// the shipped-data subtree <root>/data, and these fixtures live under
// testdata/fixtures/, outside that scope.
//
// Real upstream SHA-256 values (the actual nmap-os-db / p0f.fp / manuf / JA4+ /
// Npcap release files) are APPENDED here as they are encountered; the filename
// and content-signature layers cover the gap until a given upstream hash is
// pinned.
var KnownHashBlocklist = map[string]string{
	"1f2217917116f1a2c19a7af5a4acb10bfc8512ad69e58f7ef9af1bf02dd7cc45": "nmap-service-probes",
	"d9d29c8c4cb188dbef22b7e04d42b9285f178fbad8513f601f2cc280ae3063cf": "nmap-os-db",
	"4fd7486b0bcf0273aa4a69da1fee819d95c726b62990a2a07bd089efb4f8e397": "p0f.fp",
	"6e907afec13c621ada11d3c55d2d289bb86bc53e59eaaee8d177c92b4608dd16": "manuf (Wireshark)",
	"238140668c854143167bb5644883cc76311adb399205ac304f884614338efb63": "JA4+ server",
	"66b53b15a475e30acfb02f4595822c57512706c643673a1a5d86835fcf1fa44c": "Npcap",
	// Opaque blob (no content signature) — hash-layer isolation probe.
	"c3126c64acb02415d4be883960cacae8c284c7cdbd6287ee779756652a35857d": "known-contaminating-blob",
}

// ScanForContaminatingData walks root recursively and returns a Violation for
// every file that trips the filename layer, the content-signature layer, or the
// known-hash layer (checked in that order; first hit per file wins). A nil/empty
// slice means a clean tree. A returned error is an I/O failure during the walk,
// distinct from a governance violation (which is data, not an error).
//
// Callers (cmd/datacheck) pass the SHIPPED-DATA scope (<root>/data), never a
// whole checkout, so the repo's deliberately-contaminating testdata/fixtures/*
// are not scanned on a clean run.
func ScanForContaminatingData(root string) ([]Violation, error) {
	var violations []Violation

	// A missing scan root is not a violation and not an error: a tree with no
	// shipped data/ dir simply has nothing to govern.
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat scan root %q: %w", root, err)
	}

	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		base := filepath.Base(p)

		// Layer 1 — filename (exact basename, then glob).
		if dataset, hit := matchFilename(base); hit {
			violations = append(violations, Violation{
				Path:    p,
				Reason:  fmt.Sprintf("filename matches denylisted dataset %q", base),
				Dataset: dataset,
				Layer:   "filename",
			})
			// A single file reports one strongest signal; stop at the filename hit.
			return nil
		}

		// Layer 2 — content-signature (catches a renamed file).
		if dataset, reason, hit, scanErr := scanContent(p); scanErr != nil {
			return scanErr
		} else if hit {
			violations = append(violations, Violation{
				Path:    p,
				Reason:  reason,
				Dataset: dataset,
				Layer:   "content",
			})
			return nil
		}

		// Layer 3 — known-hash blocklist (catches an exact copy that trips no
		// content signature).
		if dataset, sum, hit, hashErr := fileHashInBlocklist(p); hashErr != nil {
			return hashErr
		} else if hit {
			violations = append(violations, Violation{
				Path:    p,
				Reason:  fmt.Sprintf("SHA-256 %s matches a known contaminating file", sum),
				Dataset: dataset,
				Layer:   "hash",
			})
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return violations, nil
}

// matchFilename applies layer 1: the exact-basename map, then the glob patterns.
func matchFilename(base string) (string, bool) {
	if dataset, hit := denylistedBasenames[base]; hit {
		return dataset, true
	}
	for _, g := range denylistedGlobs {
		if ok, _ := filepath.Match(g.pattern, base); ok {
			return g.dataset, true
		}
	}
	return "", false
}

// scanContent reads p line-by-line and reports the first content signature it
// trips. It returns (dataset, reason, matched, error).
func scanContent(p string) (string, string, bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", false, fmt.Errorf("open %q: %w", p, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow long lines (data files can have very long records).
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		for _, sig := range contentSignatures {
			if sig.re.MatchString(line) {
				return sig.dataset, fmt.Sprintf("content signature of denylisted dataset %q matched (renamed file not evading the gate)", sig.dataset), true, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		// A non-text/binary file that fails scanning is not a content match;
		// treat scan errors as "no content match" so the hash layer can still run.
		return "", "", false, nil
	}
	return "", "", false, nil
}

// fileHashInBlocklist applies layer 3: SHA-256 the whole file and look the digest
// up in KnownHashBlocklist. Returns (dataset, hexdigest, matched, error).
func fileHashInBlocklist(p string) (string, string, bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", false, fmt.Errorf("open %q: %w", p, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", false, fmt.Errorf("hash %q: %w", p, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if dataset, hit := KnownHashBlocklist[sum]; hit {
		return dataset, sum, true, nil
	}
	return "", sum, false, nil
}
