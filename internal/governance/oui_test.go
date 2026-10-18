// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package governance

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	scannerdata "github.com/cysec-watch/cysec-scanner"
)

// ouiRegistryPrefix maps each IEEE registry block to its MAC-prefix length in
// bits (D-08): MA-L is a 24-bit assignment, MA-M 28-bit, MA-S 36-bit. The
// allowlist entries for the vendored OUI snapshot MUST record exactly one of
// these {block: bits} pairs.
var ouiRegistryPrefix = map[string]int{
	"MA-L": 24,
	"MA-M": 28,
	"MA-S": 36,
}

// TestOUIPinned is the LIC-04 pin gate for the vendored IEEE OUI snapshot. For
// every allowlist entry under data/oui/, it asserts:
//   - the on-disk (embedded) file's SHA-256 equals the pin recorded in
//     data/allowlist.json, and
//   - registry_block/prefix_bits is one of the valid {MA-L:24, MA-M:28, MA-S:36}
//     pairs.
//
// It runs against the exact scannerdata.DataFS the binary ships, so a tampered
// or truncated OUI file (the T-1-08 trust-boundary threat) reddens CI.
func TestOUIPinned(t *testing.T) {
	t.Parallel()

	manifest, err := LoadAllowlist(scannerdata.DataFS)
	if err != nil {
		t.Fatalf("LoadAllowlist(scannerdata.DataFS) = %v, want nil", err)
	}

	var oui []Entry
	for _, e := range manifest {
		if len(e.Path) >= len("data/oui/") && e.Path[:len("data/oui/")] == "data/oui/" {
			oui = append(oui, e)
		}
	}
	if len(oui) != 3 {
		t.Fatalf("expected 3 OUI allowlist entries (MA-L/MA-M/MA-S), got %d", len(oui))
	}

	seenBlocks := map[string]bool{}
	for _, e := range oui {
		e := e
		t.Run(e.Path, func(t *testing.T) {
			t.Parallel()

			// SHA-256 pin match against the shipped embed.
			got, err := hashEmbedded(e.Path)
			if err != nil {
				t.Fatalf("hash %q: %v", e.Path, err)
			}
			if got != e.SHA256 {
				t.Fatalf("hash drift for %s: manifest %s, embedded %s", e.Path, e.SHA256, got)
			}

			// registry_block/prefix_bits must be a valid IEEE pair.
			wantBits, ok := ouiRegistryPrefix[e.RegistryBlock]
			if !ok {
				t.Fatalf("%s: registry_block %q is not one of MA-L/MA-M/MA-S", e.Path, e.RegistryBlock)
			}
			if e.PrefixBits != wantBits {
				t.Fatalf("%s: registry_block %s wants prefix_bits %d, got %d", e.Path, e.RegistryBlock, wantBits, e.PrefixBits)
			}
			if e.License != "NOASSERTION" {
				t.Fatalf("%s: IEEE OUI license should be NOASSERTION, got %q", e.Path, e.License)
			}
		})
		seenBlocks[e.RegistryBlock] = true
	}

	for block := range ouiRegistryPrefix {
		if !seenBlocks[block] {
			t.Errorf("missing OUI allowlist entry for registry block %s", block)
		}
	}
}

func hashEmbedded(p string) (string, error) {
	f, err := scannerdata.DataFS.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
