package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Paths are resolved relative to this package directory (go test runs with
// CWD = the package dir, internal/governance).
const (
	repoDataDir = "../../data"
	fixturesDir = "../../testdata/fixtures"
)

// contaminatingFormats enumerates every denylisted dataset with its committed
// fixture, a basename that trips the FILENAME layer, and the dataset string the
// scanner must report. Adding a new contaminating format = one row here plus a
// fixture + a KnownHashBlocklist entry.
var contaminatingFormats = []struct {
	label       string // sub-test label / fixture stem
	fixture     string // file under testdata/fixtures/
	denyName    string // basename that must trip the filename (layer 1) glob/exact
	wantDataset string // Violation.Dataset the scanner must report
}{
	{"nmap-service-probes", "nmap-service-probes.snippet", "nmap-service-probes", "nmap-service-probes"},
	{"nmap-os-db", "nmap-os-db.snippet", "nmap-os-db", "nmap-os-db"},
	{"p0f.fp", "p0f.fp.snippet", "p0f.fp", "p0f.fp"},
	{"manuf", "manuf.snippet", "manuf", "manuf (Wireshark)"},
	{"ja4_server", "ja4_server.snippet", "ja4plus_server.db", "JA4+ server"},
	{"npcap", "npcap.snippet", "npcap-oem.txt", "Npcap"},
}

// TestDenylistSeededFixture is the LIC-02 red/green gate. The red/green PAIR is
// the point: asserting only that a clean tree passes proves the scanner runs,
// not that it blocks. Every contaminating format gets a RED (planted, named →
// filename layer) and a RENAMED RED (neutral basename → content-signature layer)
// sub-test, plus the clean-tree GREEN case.
func TestDenylistSeededFixture(t *testing.T) {
	t.Parallel()

	t.Run("green: clean shipped data tree has zero violations", func(t *testing.T) {
		t.Parallel()
		vs, err := ScanForContaminatingData(repoDataDir)
		if err != nil {
			t.Fatalf("scan clean data tree: %v", err)
		}
		if len(vs) != 0 {
			t.Fatalf("clean data tree: got %d violation(s) %v, want 0", len(vs), vs)
		}
	})

	for _, f := range contaminatingFormats {
		f := f
		fixture, err := os.ReadFile(filepath.Join(fixturesDir, f.fixture))
		if err != nil {
			t.Fatalf("read %s fixture: %v", f.label, err)
		}

		t.Run("red/filename: "+f.label, func(t *testing.T) {
			t.Parallel()
			data := t.TempDir()
			if err := os.WriteFile(filepath.Join(data, f.denyName), fixture, 0o644); err != nil {
				t.Fatal(err)
			}
			vs, err := ScanForContaminatingData(data)
			if err != nil {
				t.Fatalf("scan planted %s: %v", f.label, err)
			}
			if len(vs) == 0 {
				t.Fatalf("planted %s (%s): got 0 violations, want >=1 (filename layer failed)", f.label, f.denyName)
			}
			if vs[0].Layer != "filename" {
				t.Fatalf("planted %s: layer = %q, want filename", f.label, vs[0].Layer)
			}
			if vs[0].Dataset != f.wantDataset {
				t.Fatalf("planted %s: dataset = %q, want %q", f.label, vs[0].Dataset, f.wantDataset)
			}
		})

		t.Run("red/renamed: "+f.label, func(t *testing.T) {
			t.Parallel()
			data := t.TempDir()
			// Neutral basename → the filename layer cannot match; the content-
			// signature layer (checked before the hash layer) must catch it.
			if err := os.WriteFile(filepath.Join(data, "renamed.dat"), fixture, 0o644); err != nil {
				t.Fatal(err)
			}
			vs, err := ScanForContaminatingData(data)
			if err != nil {
				t.Fatalf("scan renamed %s: %v", f.label, err)
			}
			if len(vs) == 0 {
				t.Fatalf("renamed %s: got 0 violations, want >=1 (content-signature layer failed)", f.label)
			}
			if vs[0].Layer != "content" {
				t.Fatalf("renamed %s: layer = %q, want content (content-signature must fire before hash)", f.label, vs[0].Layer)
			}
			if vs[0].Dataset != f.wantDataset {
				t.Fatalf("renamed %s: dataset = %q, want %q", f.label, vs[0].Dataset, f.wantDataset)
			}
		})
	}
}

// TestDenylistKnownHashLayer proves layer 3 in ISOLATION: an exact copy of a
// known contaminating file that trips NO content signature is still caught by
// its SHA-256, regardless of basename.
func TestDenylistKnownHashLayer(t *testing.T) {
	t.Parallel()
	// This blob matches no content signature; its digest is seeded in
	// KnownHashBlocklist as "known-contaminating-blob".
	blob := []byte("cysec-scanner hash-layer probe: opaque contaminating blob, no content signature\n")
	sum := hex.EncodeToString(func() []byte { s := sha256.Sum256(blob); return s[:] }())
	if _, ok := KnownHashBlocklist[sum]; !ok {
		t.Fatalf("probe blob digest %s is not seeded in KnownHashBlocklist", sum)
	}

	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(data, "totally-innocent-name.bin"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := ScanForContaminatingData(data)
	if err != nil {
		t.Fatalf("scan hash-probe tree: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("hash-probe: got 0 violations, want >=1 (known-hash layer failed)")
	}
	if vs[0].Layer != "hash" {
		t.Fatalf("hash-probe: layer = %q, want hash", vs[0].Layer)
	}
}

// TestKnownHashBlocklistSeededWithFixtures keeps the seed honest: every
// committed contaminating fixture's current SHA-256 must be present in
// KnownHashBlocklist (so an exact renamed copy is always caught by the hash
// layer even if the content signature is ever weakened).
func TestKnownHashBlocklistSeededWithFixtures(t *testing.T) {
	t.Parallel()
	for _, f := range contaminatingFormats {
		b, err := os.ReadFile(filepath.Join(fixturesDir, f.fixture))
		if err != nil {
			t.Fatalf("read %s fixture: %v", f.label, err)
		}
		sum := hex.EncodeToString(func() []byte { s := sha256.Sum256(b); return s[:] }())
		if _, ok := KnownHashBlocklist[sum]; !ok {
			t.Fatalf("fixture %s (sha256 %s) is not in KnownHashBlocklist", f.fixture, sum)
		}
	}
}

// TestDenylistPassesAllowlistedFormats is the adjacency guard (T-1-06): the
// denylist must NOT false-positive on allowlisted data. The IEEE OUI CSV is the
// format closest to the denylisted Wireshark manuf — both are MAC-vendor data —
// but OUI is comma-separated and public-domain-declared while manuf is tab-
// separated and GPL. The manuf tab-anchored signature must not match the CSV.
func TestDenylistPassesAllowlistedFormats(t *testing.T) {
	t.Parallel()

	t.Run("IEEE OUI CSV (comma-separated) is not flagged", func(t *testing.T) {
		t.Parallel()
		clean, err := os.ReadFile(filepath.Join(fixturesDir, "oui-clean.snippet"))
		if err != nil {
			t.Fatalf("read oui-clean fixture: %v", err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "oui.csv"), clean, 0o644); err != nil {
			t.Fatal(err)
		}
		vs, err := ScanForContaminatingData(dir)
		if err != nil {
			t.Fatalf("scan oui-clean: %v", err)
		}
		if len(vs) != 0 {
			t.Fatalf("IEEE OUI CSV false-positived as contaminating: %v", vs)
		}
	})

	t.Run("vendored Recog XML is not flagged", func(t *testing.T) {
		t.Parallel()
		recog := filepath.Join(repoDataDir, "recog")
		if _, err := os.Stat(recog); err != nil {
			t.Skipf("recog data dir not present: %v", err)
		}
		vs, err := ScanForContaminatingData(recog)
		if err != nil {
			t.Fatalf("scan recog dir: %v", err)
		}
		if len(vs) != 0 {
			t.Fatalf("allowlisted recog data flagged as contaminating: %v", vs)
		}
	})
}

// TestDenylistMissingRootIsClean proves a nonexistent scan root is reported as
// zero violations (not an error) — the cmd/datacheck "<root>/data absent"
// contract.
func TestDenylistMissingRootIsClean(t *testing.T) {
	t.Parallel()
	vs, err := ScanForContaminatingData(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("missing root: got err %v, want nil", err)
	}
	if len(vs) != 0 {
		t.Fatalf("missing root: got %d violations, want 0", len(vs))
	}
}
