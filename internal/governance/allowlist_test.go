package governance

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"testing/fstest"

	scannerdata "github.com/cysec-watch/cysec-scanner"
)

// TestAllowlistIntegrity is the LIC-03 gate against the REAL shipped embed.FS:
// every embedded data file is on the allowlist with a matching SHA-256 and
// every allowlist entry has a present embedded file. It runs against the exact
// scannerdata.DataFS the binary ships.
func TestAllowlistIntegrity(t *testing.T) {
	t.Parallel()
	if err := VerifyEmbeddedData(scannerdata.DataFS); err != nil {
		t.Fatalf("VerifyEmbeddedData(scannerdata.DataFS) = %v, want nil", err)
	}
}

func sha256hex(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// buildFS constructs a synthetic embedded-data FS: a data/allowlist.json built
// from the given manifest JSON plus the given data files.
func buildFS(allowlistJSON string, files map[string][]byte) fstest.MapFS {
	m := fstest.MapFS{
		allowlistPath: &fstest.MapFile{Data: []byte(allowlistJSON)},
	}
	for p, b := range files {
		m[p] = &fstest.MapFile{Data: b}
	}
	return m
}

// TestAllowlistIntegrityTwoWay proves both directions of the match and the
// edge cases called out in the plan's must-have truths.
func TestAllowlistIntegrityTwoWay(t *testing.T) {
	t.Parallel()

	foo := []byte("hello recog\n")

	t.Run("single entry valid", func(t *testing.T) {
		t.Parallel()
		al := fmt.Sprintf(`{"schema_version":1,"entries":[{"path":"data/foo.xml","sha256":"%s","license":"BSD-2-Clause","provenance_url":"https://example/foo"}]}`, sha256hex(foo))
		fsys := buildFS(al, map[string][]byte{"data/foo.xml": foo})
		if err := VerifyEmbeddedData(fsys); err != nil {
			t.Fatalf("valid single-entry manifest: got err %v, want nil", err)
		}
	})

	t.Run("empty data set", func(t *testing.T) {
		t.Parallel()
		al := `{"schema_version":1,"entries":[]}`
		fsys := buildFS(al, nil) // only the allowlist.json, no data files
		if err := VerifyEmbeddedData(fsys); err != nil {
			t.Fatalf("empty data set: got err %v, want nil", err)
		}
	})

	t.Run("manifest entry without embedded file fails", func(t *testing.T) {
		t.Parallel()
		al := `{"schema_version":1,"entries":[{"path":"data/ghost.xml","sha256":"00","license":"BSD-2-Clause","provenance_url":"https://example/ghost"}]}`
		fsys := buildFS(al, nil) // entry references a file that is not present
		if err := VerifyEmbeddedData(fsys); err == nil {
			t.Fatal("manifest entry without embedded file: got nil, want error")
		}
	})

	t.Run("embedded file without manifest entry fails", func(t *testing.T) {
		t.Parallel()
		al := `{"schema_version":1,"entries":[]}`
		fsys := buildFS(al, map[string][]byte{"data/orphan.xml": foo}) // present but unlisted
		if err := VerifyEmbeddedData(fsys); err == nil {
			t.Fatal("embedded file without manifest entry: got nil, want error")
		}
	})

	t.Run("hash drift fails", func(t *testing.T) {
		t.Parallel()
		al := fmt.Sprintf(`{"schema_version":1,"entries":[{"path":"data/foo.xml","sha256":"%s","license":"BSD-2-Clause","provenance_url":"https://example/foo"}]}`, sha256hex([]byte("different content")))
		fsys := buildFS(al, map[string][]byte{"data/foo.xml": foo})
		if err := VerifyEmbeddedData(fsys); err == nil {
			t.Fatal("hash drift: got nil, want error")
		}
	})
}

// TestAllowlistOrderingIndependent proves integrity is independent of entry
// order in allowlist.json (the manifest is consumed as a map keyed by path,
// not positionally).
func TestAllowlistOrderingIndependent(t *testing.T) {
	t.Parallel()
	a := []byte("file a\n")
	b := []byte("file b\n")
	files := map[string][]byte{"data/a.xml": a, "data/b.xml": b}

	entryA := fmt.Sprintf(`{"path":"data/a.xml","sha256":"%s","license":"X","provenance_url":"u"}`, sha256hex(a))
	entryB := fmt.Sprintf(`{"path":"data/b.xml","sha256":"%s","license":"X","provenance_url":"u"}`, sha256hex(b))

	forward := fmt.Sprintf(`{"schema_version":1,"entries":[%s,%s]}`, entryA, entryB)
	reverse := fmt.Sprintf(`{"schema_version":1,"entries":[%s,%s]}`, entryB, entryA)

	if err := VerifyEmbeddedData(buildFS(forward, files)); err != nil {
		t.Fatalf("forward order: got err %v, want nil", err)
	}
	if err := VerifyEmbeddedData(buildFS(reverse, files)); err != nil {
		t.Fatalf("reverse order: got err %v, want nil", err)
	}
}

// TestLoadAllowlistStrict proves the strict parser rejects unknown keys and
// duplicate paths (extra="forbid" parity).
func TestLoadAllowlistStrict(t *testing.T) {
	t.Parallel()

	t.Run("unknown top-level key rejected", func(t *testing.T) {
		t.Parallel()
		fsys := buildFS(`{"schema_version":1,"entries":[],"bogus":true}`, nil)
		if _, err := LoadAllowlist(fsys); err == nil {
			t.Fatal("unknown top-level key: got nil, want error")
		}
	})

	t.Run("unknown entry key rejected", func(t *testing.T) {
		t.Parallel()
		fsys := buildFS(`{"schema_version":1,"entries":[{"path":"data/x","sha256":"ab","license":"X","provenance_url":"u","surprise":1}]}`, nil)
		if _, err := LoadAllowlist(fsys); err == nil {
			t.Fatal("unknown entry key: got nil, want error")
		}
	})

	t.Run("duplicate path rejected", func(t *testing.T) {
		t.Parallel()
		fsys := buildFS(`{"schema_version":1,"entries":[{"path":"data/x","sha256":"ab","license":"X","provenance_url":"u"},{"path":"data/x","sha256":"cd","license":"X","provenance_url":"u"}]}`, nil)
		if _, err := LoadAllowlist(fsys); err == nil {
			t.Fatal("duplicate path: got nil, want error")
		}
	})
}
