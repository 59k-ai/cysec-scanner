// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package capabilities

import (
	"bytes"
	"os"
	"testing"
)

// TestLLInfoListsUsableMAC pins the sysctl half of the darwin arp_cache rule: an
// entitled (or root) process sees neighbour entries with real MACs; without
// them the dump is empty, and a dump holding only the 02:00:00:00:00:00
// placeholder or incomplete entries does not count as readable.
func TestLLInfoListsUsableMAC(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../netutil/testdata/rt-llinfo-root.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !llinfoListsUsableMAC(b) {
		t.Error("root capture: want readable")
	}
	if llinfoListsUsableMAC(nil) {
		t.Error("empty dump (hidden cache): want not readable")
	}
	red := bytes.Replace(b, []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01},
		[]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}, 1)
	if llinfoListsUsableMAC(red) {
		t.Error("placeholder-only dump: want not readable")
	}
}
