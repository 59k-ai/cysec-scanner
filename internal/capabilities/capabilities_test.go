// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package capabilities

import "testing"

// TestDetectReturnsValue proves Detect() runs without panic and returns a value
// struct (the three probes are best-effort and never fatal).
func TestDetectReturnsValue(t *testing.T) {
	t.Parallel()
	_ = Detect() // must not panic regardless of runtime permissions
}

// TestImmutableByValue proves ENG-06 immutability: a copy of a Capabilities
// value shares no mutable state with the original, so passing it by value to a
// stage can never alter the detected truth.
func TestImmutableByValue(t *testing.T) {
	t.Parallel()
	orig := Capabilities{UnprivilegedICMP: true, SystemPing: true, ARPCache: true}
	cp := orig
	cp.UnprivilegedICMP = false
	cp.SystemPing = false
	cp.ARPCache = false

	if !orig.UnprivilegedICMP || !orig.SystemPing || !orig.ARPCache {
		t.Fatalf("mutating a copy altered the original %+v — Capabilities is not immutable by value", orig)
	}
}

// TestARPOutputListsEntries pins the darwin ARP-cache readability rule. macOS 27
// hides the IPv4 neighbour cache from unprivileged processes: `arp -an` prints
// nothing at all, although the binary exists. A readable cache always lists at
// least the interface's own permanent entry, even when every neighbour is still
// "(incomplete)". So "readable" means at least one entry line, not "arp is on
// PATH" (which made --describe claim arp_cache:true on a hidden cache).
func TestARPOutputListsEntries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"hidden (macOS 27 unprivileged)", "", false},
		{"whitespace only", "\n  \n", false},
		{"readable", "? (192.168.1.1) at 74:24:9f:96:90:57 on en0 ifscope [ethernet]\n", true},
		{"readable, neighbours incomplete", "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n", true},
	}
	for _, c := range cases {
		if got := arpOutputListsEntries(c.out); got != c.want {
			t.Errorf("%s: arpOutputListsEntries = %v, want %v", c.name, got, c.want)
		}
	}
}
