package governance

import (
	"os"
	"path/filepath"
	"testing"
)

// repoDataDir and fixtureFile are resolved relative to this package directory
// (go test runs with CWD = the package dir, internal/governance).
const (
	repoDataDir = "../../data"
	fixtureFile = "../../testdata/fixtures/nmap-service-probes.snippet"
)

// TestDenylistSeededFixture is the LIC-02 red/green gate. The red/green PAIR is
// the point: asserting only that a clean tree passes proves the scanner runs,
// not that it blocks.
func TestDenylistSeededFixture(t *testing.T) {
	t.Parallel()

	fixture, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatalf("read red fixture: %v", err)
	}

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

	t.Run("red: planted nmap-service-probes caught by filename layer", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		data := filepath.Join(dir, "data")
		if err := os.MkdirAll(data, 0o755); err != nil {
			t.Fatal(err)
		}
		// Exact denylisted basename → layer 1 (filename glob).
		if err := os.WriteFile(filepath.Join(data, "nmap-service-probes"), fixture, 0o644); err != nil {
			t.Fatal(err)
		}
		vs, err := ScanForContaminatingData(data)
		if err != nil {
			t.Fatalf("scan planted tree: %v", err)
		}
		if len(vs) == 0 {
			t.Fatal("planted nmap-service-probes: got 0 violations, want >=1 (filename layer failed)")
		}
	})

	t.Run("red: RENAMED fixture still caught by content-signature layer", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		data := filepath.Join(dir, "data")
		if err := os.MkdirAll(data, 0o755); err != nil {
			t.Fatal(err)
		}
		// Neutral basename → the filename layer cannot match; only the
		// content-signature layer can catch this.
		if err := os.WriteFile(filepath.Join(data, "vendors.txt"), fixture, 0o644); err != nil {
			t.Fatal(err)
		}
		vs, err := ScanForContaminatingData(data)
		if err != nil {
			t.Fatalf("scan renamed tree: %v", err)
		}
		if len(vs) == 0 {
			t.Fatal("renamed fixture: got 0 violations, want >=1 (content-signature layer failed)")
		}
		if vs[0].Dataset != "nmap-service-probes" {
			t.Fatalf("renamed fixture: dataset = %q, want nmap-service-probes", vs[0].Dataset)
		}
	})
}

// TestDenylistNoFalsePositiveOnAllowlisted proves the LIC-03 adjacency truth:
// the allowlisted Recog XML passes the denylist gate (no false positive on
// permissive, allowlisted data).
func TestDenylistNoFalsePositiveOnAllowlisted(t *testing.T) {
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
