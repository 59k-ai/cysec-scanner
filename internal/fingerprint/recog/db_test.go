// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package recog

import (
	"strings"
	"testing"
	"testing/fstest"

	scannerdata "github.com/cysec-watch/cysec-scanner"
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
