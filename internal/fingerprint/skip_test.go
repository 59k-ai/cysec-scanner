// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import "testing"

// TestFragileSkipTruthTable proves the skip predicate over the real asset_type
// enum and the OUI vendor lists: printer/iot/network are fragile; server/
// workstation/unknown/empty are not; an OUI networking-gear or IoT-maker match is
// fragile even when the asset_type is unknown; and a host with neither a fragile
// verdict nor an OUI match defaults to not-fragile (probing allowed).
func TestFragileSkipTruthTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		assetType string
		ouiVendor string
		want      bool
	}{
		{"printer", "printer", "", true},
		{"iot", "iot", "", true},
		{"network", "network", "", true},
		{"server not fragile", "server", "", false},
		{"workstation not fragile", "workstation", "", false},
		{"unknown not fragile", "unknown", "", false},
		{"empty not fragile", "", "", false},
		{"network vendor OUI, unknown type", "unknown", "cisco systems, inc", true},
		{"iot vendor OUI, unknown type", "unknown", "espressif inc.", true},
		{"unrelated vendor OUI not fragile", "unknown", "contoso widgets gmbh", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldSkipIntrusiveProbe(c.assetType, c.ouiVendor, false); got != c.want {
				t.Errorf("shouldSkipIntrusiveProbe(%q, %q, false) = %v, want %v",
					c.assetType, c.ouiVendor, got, c.want)
			}
		})
	}
}

// TestProbeFragileOverrideWinsFirst proves the --probe-fragile override is checked
// FIRST and wins unconditionally: every input that would otherwise be skipped
// (fragile asset_type, OUI match, and a fragile host that also carries a strong OS
// signal) returns false when probeFragile is true.
func TestProbeFragileOverrideWinsFirst(t *testing.T) {
	t.Parallel()
	fragileInputs := []struct {
		assetType string
		ouiVendor string
	}{
		{"printer", ""},
		{"iot", ""},
		{"network", "cisco systems"},
		{"unknown", "espressif"},
		{"unknown", "mikrotik routerboard"},
	}
	for _, in := range fragileInputs {
		// Without the override these are all fragile (skip = true).
		if !shouldSkipIntrusiveProbe(in.assetType, in.ouiVendor, false) {
			t.Fatalf("precondition: %+v should be fragile without override", in)
		}
		// With the override the predicate returns false for every one of them.
		if shouldSkipIntrusiveProbe(in.assetType, in.ouiVendor, true) {
			t.Errorf("probeFragile override did not win for %+v", in)
		}
	}
}

// TestProbeFragileSkipWinsOverSignal proves that, absent the override, a host that
// is BOTH fragile and would carry a strong OS signal is still skipped — the skip
// wins over the signal. The predicate takes no signal argument by design: a strong
// passive os_guess does not unlock intrusive probing; only --probe-fragile does.
func TestProbeFragileSkipWinsOverSignal(t *testing.T) {
	t.Parallel()
	// A printer with (implicitly) a strong OS signal: skip stays true unless the
	// operator overrides.
	if !shouldSkipIntrusiveProbe("printer", "", false) {
		t.Error("fragile host with a strong signal must still be skipped without override")
	}
	if shouldSkipIntrusiveProbe("printer", "", true) {
		t.Error("override must unlock the fragile-with-signal host")
	}
}
