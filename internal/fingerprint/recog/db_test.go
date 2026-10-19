// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package recog

import (
	"strings"
	"testing"
	"testing/fstest"

	scannerdata "github.com/59k-ai/cysec-scanner"
)

const sshDBPath = "data/recog/ssh_banners.xml"

// embeddedDropCeiling is the documented maximum number of fingerprints the
// embedded SSH database may fail to compile under RE2. The SSH database is
// verified 100% RE2-clean, so the ceiling is 0; a regression that vendors an
// incompatible pattern trips this gate rather than silently dropping coverage.
const embeddedDropCeiling = 0

// TestEmbeddedDBCompiles proves every fingerprint in the embedded SSH database
// compiles under RE2 with a drop-count at or below the documented ceiling — the
// corpus gate and the never-crash loader gate (FPRINT-01, Pitfall 2).
func TestEmbeddedDBCompiles(t *testing.T) {
	t.Parallel()
	db, err := Load(scannerdata.DataFS, sshDBPath)
	if err != nil {
		t.Fatalf("load embedded SSH database: %v", err)
	}
	if db.Total() == 0 {
		t.Fatal("embedded SSH database declared zero fingerprints")
	}
	if db.Dropped() > embeddedDropCeiling {
		t.Fatalf("dropped %d fingerprints, ceiling %d", db.Dropped(), embeddedDropCeiling)
	}
	if len(db.compiled) != db.Total()-db.Dropped() {
		t.Fatalf("compiled %d != total %d - dropped %d", len(db.compiled), db.Total(), db.Dropped())
	}
}

// TestEmbeddedDBGoldenExamplesSelfMatch proves each fingerprint that carries a
// golden <example> self-matches its own pattern and yields the expected param
// values (FPRINT-01 corpus gate).
func TestEmbeddedDBGoldenExamplesSelfMatch(t *testing.T) {
	t.Parallel()
	db, err := Load(scannerdata.DataFS, sshDBPath)
	if err != nil {
		t.Fatalf("load embedded SSH database: %v", err)
	}
	examples := 0
	for _, c := range db.compiled {
		for _, ex := range c.examples {
			if strings.TrimSpace(ex.Text) == "" {
				continue
			}
			examples++
			m := c.re.FindStringSubmatch(ex.Text)
			if m == nil {
				t.Errorf("example %q did not self-match its pattern %q", ex.Text, c.re.String())
				continue
			}
			vals := extractParams(c.params, m)
			for _, attr := range ex.Attrs {
				name := attr.Name.Local
				if got, ok := vals[name]; ok && got != attr.Value {
					t.Errorf("example %q: param %q = %q, want %q", ex.Text, name, got, attr.Value)
				}
			}
		}
	}
	if examples == 0 {
		t.Fatal("no golden examples found in the embedded SSH database")
	}
}

// TestRecogOrderFirstMatchWins proves that when two fingerprints both match the
// same banner, the first in declaration order wins (stable tiebreak).
func TestRecogOrderFirstMatchWins(t *testing.T) {
	t.Parallel()
	const xml = `<?xml version='1.0'?>
<fingerprints matches="ssh.banner" protocol="ssh" preference="0.90">
  <fingerprint pattern="^Dup_(.*)$">
    <param pos="0" name="service.product" value="FirstProduct"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
  <fingerprint pattern="^Dup_(.*)$">
    <param pos="0" name="service.product" value="SecondProduct"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>`
	db := loadString(t, xml)
	id, ok := db.Match("Dup_1.0")
	if !ok {
		t.Fatal("expected a match")
	}
	if id.Product != "FirstProduct" {
		t.Errorf("first-match-wins violated: product = %q, want FirstProduct", id.Product)
	}
}

// TestNeverRaisesSkipsUncompilablePattern proves a pattern RE2 rejects is skipped
// and counted rather than crashing the loader (D-14).
func TestNeverRaisesSkipsUncompilablePattern(t *testing.T) {
	t.Parallel()
	// A backreference is valid in a backtracking dialect but RE2 rejects it.
	const xml = `<?xml version='1.0'?>
<fingerprints matches="ssh.banner" protocol="ssh" preference="0.90">
  <fingerprint pattern="^(a)\1$">
    <param pos="0" name="service.product" value="Backref"/>
  </fingerprint>
  <fingerprint pattern="^Good_(.*)$">
    <param pos="0" name="service.product" value="Good"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>`
	db := loadString(t, xml)
	if db.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1 (the backreference pattern)", db.Dropped())
	}
	if id, ok := db.Match("Good_2.0"); !ok || id.Product != "Good" {
		t.Errorf("surviving fingerprint did not match: %+v ok=%v", id, ok)
	}
}

// TestNeverRaisesSanitizesCapturedParam proves a value captured from an untrusted
// banner is control-char stripped and length-capped before it leaves the matcher
// (ASVS V5).
func TestNeverRaisesSanitizesCapturedParam(t *testing.T) {
	t.Parallel()
	const xml = `<?xml version='1.0'?>
<fingerprints matches="ssh.banner" protocol="ssh" preference="0.90">
  <fingerprint pattern="^Evil_(.*)$">
    <param pos="0" name="service.product" value="Evil"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>`
	db := loadString(t, xml)
	hostile := "Evil_1.0\x00\x1b[31m" + strings.Repeat("A", 10000)
	id, ok := db.Match(hostile)
	if !ok {
		t.Fatal("expected a match")
	}
	if strings.ContainsAny(id.ServiceVersion, "\x00\x1b") {
		t.Errorf("captured version carries control chars: %q", id.ServiceVersion)
	}
	if len(id.ServiceVersion) > maxParamBytes {
		t.Errorf("captured version not length-capped: %d bytes, cap %d", len(id.ServiceVersion), maxParamBytes)
	}
}

// TestCPEInterpolation proves a {service.version} token in a CPE template is
// replaced with the captured version.
func TestCPEInterpolation(t *testing.T) {
	t.Parallel()
	const xml = `<?xml version='1.0'?>
<fingerprints matches="ssh.banner" protocol="ssh" preference="0.90">
  <fingerprint pattern="^OpenSSH_(\d+\.\d+)$">
    <param pos="0" name="service.product" value="OpenSSH"/>
    <param pos="1" name="service.version"/>
    <param pos="0" name="service.cpe23" value="cpe:/a:openbsd:openssh:{service.version}"/>
  </fingerprint>
</fingerprints>`
	db := loadString(t, xml)
	id, ok := db.Match("OpenSSH_9.6")
	if !ok {
		t.Fatal("expected a match")
	}
	if id.CPE != "cpe:/a:openbsd:openssh:9.6" {
		t.Errorf("cpe interpolation = %q, want cpe:/a:openbsd:openssh:9.6", id.CPE)
	}
}

// TestMatchEmptyBannerNoMatch proves an empty banner never matches and never
// panics.
func TestMatchEmptyBannerNoMatch(t *testing.T) {
	t.Parallel()
	db := loadString(t, `<?xml version='1.0'?>
<fingerprints matches="ssh.banner" protocol="ssh"><fingerprint pattern="^x$"><param pos="0" name="service.product" value="X"/></fingerprint></fingerprints>`)
	if _, ok := db.Match(""); ok {
		t.Error("empty banner should not match")
	}
}

const recogCorpusDir = "data/recog"

// corpusDropCeiling is the documented maximum number of fingerprints the WHOLE
// embedded Recog corpus may fail to compile under RE2. Every vendored file at the
// pinned upstream commit is measured 100% RE2-clean (0 drops), so the ceiling is
// 0. Because the data is sha256-pinned by the allowlist, the drop count cannot
// drift without a visible hash change; a future re-vendor that introduces a
// backtracking/lookaround pattern trips this gate rather than silently shrinking
// coverage (FPRINT-01, Pitfall 2, D-14).
const corpusDropCeiling = 0

// corpusSelfMatchFailureCeiling documents, per file, how many golden <example>
// strings do NOT self-match their own fingerprint's pattern under stdlib RE2.
// These are upstream data quirks at the pinned 2015-era rapid7/recog commit —
// an example whose literal case or trailing newline differs from its own
// case-sensitive, anchored pattern (e.g. "FTP server" vs a pattern matching
// "FTP Server"). They are NOT RE2-compile failures (every pattern compiles) and
// NOT matcher bugs; they are examples that would not match their own fingerprint
// in any engine. The counts are measured against the pinned data; a file absent
// from the map must have ZERO self-match failures. Because the corpus is
// sha256-pinned, these counts are stable — a future re-vendor that regresses
// self-match coverage trips this gate.
var corpusSelfMatchFailureCeiling = map[string]int{
	"data/recog/ftp_banners.xml":    18,
	"data/recog/telnet_banners.xml": 17,
}

// TestCorpusLoadsWithinDropCeiling proves the whole embedded data/recog/ tree
// loads without panic and that the per-file and total RE2 drop-counts stay at or
// below the documented ceiling (FPRINT-01 corpus gate, D-14 graceful degradation).
func TestCorpusLoadsWithinDropCeiling(t *testing.T) {
	t.Parallel()
	c, err := LoadCorpus(scannerdata.DataFS, recogCorpusDir)
	if err != nil {
		t.Fatalf("load embedded Recog corpus: %v", err)
	}
	if c.TotalFingerprints() == 0 {
		t.Fatal("embedded Recog corpus declared zero fingerprints")
	}
	if got := c.TotalDropped(); got > corpusDropCeiling {
		t.Errorf("corpus total dropped = %d, ceiling %d", got, corpusDropCeiling)
	}
	for path, dropped := range c.DroppedByFile() {
		if dropped > corpusDropCeiling {
			t.Errorf("%s: dropped %d, per-file ceiling %d", path, dropped, corpusDropCeiling)
		}
	}
	// The curated banner-yielding subset must all be present and embedded.
	wantFiles := []string{
		"data/recog/ftp_banners.xml",
		"data/recog/http_servers.xml",
		"data/recog/imap_banners.xml",
		"data/recog/pop_banners.xml",
		"data/recog/smtp_banners.xml",
		"data/recog/ssh_banners.xml",
		"data/recog/telnet_banners.xml",
	}
	got := c.DroppedByFile()
	for _, f := range wantFiles {
		if _, ok := got[f]; !ok {
			t.Errorf("curated corpus missing expected file %s", f)
		}
	}
}

// TestCorpusGoldenExamplesSelfMatch proves that, across the whole corpus, each
// fingerprint's golden <example> self-matches its own pattern and resolves to the
// declared param values. Base64-encoded examples decode without error (hard
// gate). The small number of upstream examples that do not self-match their own
// case-sensitive/anchored pattern is bounded per file by a documented ceiling
// (see corpusSelfMatchFailureCeiling) (FPRINT-01 corpus gate).
func TestCorpusGoldenExamplesSelfMatch(t *testing.T) {
	t.Parallel()
	c, err := LoadCorpus(scannerdata.DataFS, recogCorpusDir)
	if err != nil {
		t.Fatalf("load embedded Recog corpus: %v", err)
	}

	totalExamples := 0
	for i, db := range c.dbs {
		path := c.paths[i]
		failures := 0
		fileExamples := 0
		for _, cf := range db.compiled {
			for _, ex := range cf.examples {
				banner, ok := ex.decodedBanner()
				if !ok {
					t.Errorf("%s: example declared _encoding=base64 but did not decode: %q", path, ex.Text)
					continue
				}
				if strings.TrimSpace(banner) == "" {
					continue
				}
				fileExamples++
				totalExamples++
				m := cf.re.FindStringSubmatch(banner)
				if m == nil {
					failures++
					continue
				}
				vals := extractParams(cf.params, m)
				for _, attr := range ex.Attrs {
					name := attr.Name.Local
					if got, ok := vals[name]; ok && got != attr.Value {
						t.Errorf("%s: example %q param %q = %q, want %q", path, banner, name, got, attr.Value)
					}
				}
			}
		}
		ceiling := corpusSelfMatchFailureCeiling[path]
		if failures > ceiling {
			t.Errorf("%s: %d/%d golden examples failed to self-match, ceiling %d", path, failures, fileExamples, ceiling)
		}
	}
	if totalExamples == 0 {
		t.Fatal("no golden examples found across the embedded Recog corpus")
	}
}

// TestCorpusPerProtocolResolves proves a representative banner for each
// banner-yielding protocol resolves to a Recog identity via the matcher — the
// FPRINT-01 coverage completion across the Phase-4 port set. Service protocols
// resolve to a product/version; telnet resolves to an OS cue (its fingerprints
// carry os.*/hw.* rather than a service product), which is an honest Recog
// identity for a login-prompt banner.
func TestCorpusPerProtocolResolves(t *testing.T) {
	t.Parallel()
	c, err := LoadCorpus(scannerdata.DataFS, recogCorpusDir)
	if err != nil {
		t.Fatalf("load embedded Recog corpus: %v", err)
	}

	cases := []struct {
		protocol    string
		banner      string
		wantProduct string
		wantVersion string
		wantOSFam   string
	}{
		{"http", "nginx/1.4.6", "nginx", "1.4.6", ""},
		{"ftp", "foo.bar Microsoft FTP Service (Version 3.0).", "IIS", "3.0", "Windows"},
		{"smtp", "X1 NT-ESMTP Server foo.bar (IMail 6.06 EVAL 11347-1)", "IMail Server", "6.06", ""},
		{"pop3", "foo Cyrus POP3 v2.3", "Cyrus POP", "2.3", ""},
		{"imap", "Microsoft Exchange IMAP4rev1 server version 5.5.2448.8 (foo.bar) ready", "Exchange Server 5.5", "5.5.2448.8", "Windows"},
		{"telnet", "RT-AC54U login:", "", "", "Linux"},
	}
	for _, tc := range cases {
		db := c.DatabaseForProtocol(tc.protocol)
		if db == nil {
			t.Errorf("%s: no database for protocol in corpus", tc.protocol)
			continue
		}
		id, ok := db.Match(tc.banner)
		if !ok {
			t.Errorf("%s: banner %q did not resolve to any Recog identity", tc.protocol, tc.banner)
			continue
		}
		if id.Product != tc.wantProduct {
			t.Errorf("%s: product = %q, want %q", tc.protocol, id.Product, tc.wantProduct)
		}
		if id.ServiceVersion != tc.wantVersion {
			t.Errorf("%s: version = %q, want %q", tc.protocol, id.ServiceVersion, tc.wantVersion)
		}
		if id.OSFamily != tc.wantOSFam {
			t.Errorf("%s: os-family = %q, want %q", tc.protocol, id.OSFamily, tc.wantOSFam)
		}
	}
}

// TestCorpusMatchFirstMatchWinsDeterministic proves that when the SAME banner
// matches a fingerprint in two different corpus files, the file sorted first by
// path wins — a deterministic, run-stable corpus-wide first-match-wins
// (FPRINT-03 ordering edge, corpus-wide).
func TestCorpusMatchFirstMatchWinsDeterministic(t *testing.T) {
	t.Parallel()
	const first = `<?xml version='1.0'?>
<fingerprints matches="a.banner" protocol="a" preference="0.90">
  <fingerprint pattern="^Dup_(.*)$">
    <param pos="0" name="service.product" value="FromFileA"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>`
	const second = `<?xml version='1.0'?>
<fingerprints matches="b.banner" protocol="b" preference="0.90">
  <fingerprint pattern="^Dup_(.*)$">
    <param pos="0" name="service.product" value="FromFileB"/>
    <param pos="1" name="service.version"/>
  </fingerprint>
</fingerprints>`
	fsys := fstest.MapFS{
		"data/recog/a_banners.xml": {Data: []byte(first)},
		"data/recog/b_banners.xml": {Data: []byte(second)},
	}
	c, err := LoadCorpus(fsys, recogCorpusDir)
	if err != nil {
		t.Fatalf("load in-memory corpus: %v", err)
	}
	id, ok := c.Match("Dup_1.0")
	if !ok {
		t.Fatal("expected a corpus match")
	}
	if id.Product != "FromFileA" {
		t.Errorf("corpus first-match-wins violated: product = %q, want FromFileA (sorted-first path)", id.Product)
	}
}

// loadString loads a DB from an in-memory XML document at the embedded SSH path.
func loadString(t *testing.T, xml string) *DB {
	t.Helper()
	fsys := fstest.MapFS{sshDBPath: {Data: []byte(xml)}}
	db, err := Load(fsys, sshDBPath)
	if err != nil {
		t.Fatalf("load in-memory db: %v", err)
	}
	return db
}
