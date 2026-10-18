package governance

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// Violation records one denylist hit: the offending file, a human-readable
// reason, and which contaminating dataset signature matched.
type Violation struct {
	Path    string // path to the offending file (as walked)
	Reason  string // why it was flagged
	Dataset string // the contaminating dataset it matched (e.g. "nmap-service-probes")
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s (dataset: %s)", v.Path, v.Reason, v.Dataset)
}

// denylistedBasenames is the FILENAME layer (layer 1): exact basenames of known
// contaminating data files. This plan (01-01) ships only the nmap-service-probes
// entry to prove the mechanism end-to-end.
//
// EXTENSION POINT (Plan 01-02): the full contaminating set is added here and in
// contentSignatures below — nmap-os-db, p0f.fp, Wireshark manuf, JA4+ server
// data, Npcap (*.npl) — plus a layer-3 known-hash blocklist and the
// go-licenses dependency-license gate. Keep the filename and content layers in
// lockstep: a filename entry MUST have a matching content signature so a
// renamed file is still caught.
//
// NOT DENYLISTED — JARM: JARM (salesforce/jarm) is BSD-3-Clause with no patent
// grant and no asserted/pending patent, so it is permissive and allowlist-
// eligible (see 01-RESEARCH.md "JARM — ALLOWLIST"). Do NOT add JARM here. Its
// look-alike JA4+ (FoxIO-License-1.1, patent-pending) IS a denylist target and
// lands in Plan 01-02. Never write a generic "TLS fingerprinting" entry — name
// JA4+ specifically.
var denylistedBasenames = map[string]string{
	"nmap-service-probes": "nmap-service-probes",
}

// contentSignatures is the CONTENT-SIGNATURE layer (layer 2): regexes that
// catch a RENAMED contaminating file whose basename was changed to evade the
// filename layer. Each regex is matched per-line (MustCompile anchors with ^).
//
// nmap-service-probes lines begin with Probe/match/softmatch/ports/Exclude
// directives — a format no permissive dataset in this repo uses (verified
// against the vendored Recog XML, which is indented XML and matches none of
// these). EXTENSION POINT (Plan 01-02): add nmap-os-db (^Fingerprint / ^SEQ\(),
// p0f.fp (^\[.*:.*:.*\] / ^sig *=), and Wireshark manuf (^[0-9A-Fa-f]{2}:...)
// signatures here.
var contentSignatures = map[string]*regexp.Regexp{
	"nmap-service-probes": regexp.MustCompile(`^(Probe|match|softmatch|ports|Exclude) `),
}

// ScanForContaminatingData walks root recursively and returns a Violation for
// every file that trips the filename layer or the content-signature layer. A
// nil/empty slice means a clean tree. A returned error is an I/O failure during
// the walk, distinct from a governance violation (which is data, not an error).
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

		// Layer 1 — filename glob (exact basename).
		if dataset, hit := denylistedBasenames[base]; hit {
			violations = append(violations, Violation{
				Path:    p,
				Reason:  fmt.Sprintf("filename matches denylisted dataset basename %q", base),
				Dataset: dataset,
			})
			// Keep scanning content too so a single file can report the
			// strongest signal, but avoid double-counting the same dataset:
			// if the filename already flagged it, skip the content pass for
			// that file.
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
			})
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return violations, nil
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
		for dataset, re := range contentSignatures {
			if re.MatchString(line) {
				return dataset, fmt.Sprintf("content signature of denylisted dataset %q matched (renamed file not evading the gate)", dataset), true, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		// A non-text/binary file that fails scanning is not a violation; treat
		// scan errors as "no content match" rather than failing the gate.
		return "", "", false, nil
	}
	return "", "", false, nil
}
