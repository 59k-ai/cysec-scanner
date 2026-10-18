// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"testing"

	"golang.org/x/time/rate"
)

// TestTimingTiers pins the PORT-03 contract: three distinct named tiers with a
// polite default, strictly increasing load as politeness decreases, and every
// tier production-safe (positive budgets, a floor no higher than the ceiling,
// and a bounded — never unbounded — aggressive ceiling, D-03/D-04).
func TestTimingTiers(t *testing.T) {
	polite := ResolveTier("polite")
	normal := ResolveTier("normal")
	aggressive := ResolveTier("aggressive")

	// Polite is the safe default for an empty or unrecognized timing name.
	for _, name := range []string{"", "insane", "T5", "POLITE", "nonsense"} {
		got := ResolveTier(name)
		if got != polite {
			t.Errorf("ResolveTier(%q) = %+v, want the polite tier %+v", name, got, polite)
		}
	}

	// PPS and Workers strictly increase polite -> normal -> aggressive.
	if !(polite.PPS < normal.PPS && normal.PPS < aggressive.PPS) {
		t.Errorf("PPS not strictly increasing: polite=%v normal=%v aggressive=%v",
			polite.PPS, normal.PPS, aggressive.PPS)
	}
	if !(polite.Workers < normal.Workers && normal.Workers < aggressive.Workers) {
		t.Errorf("Workers not strictly increasing: polite=%v normal=%v aggressive=%v",
			polite.Workers, normal.Workers, aggressive.Workers)
	}

	// polite stays in the low hundreds (conservative, D-04).
	if polite.PPS > 200 {
		t.Errorf("polite.PPS = %v, want a conservative low-hundreds ceiling (<=200)", polite.PPS)
	}
	// aggressive is bounded — no sentinel / unbounded / infinite rate (D-03).
	if aggressive.PPS <= 0 || aggressive.PPS > 2000 {
		t.Errorf("aggressive.PPS = %v, want a finite bounded ceiling (0 < pps <= 2000)", aggressive.PPS)
	}

	// Every tier is well-formed: positive budgets, FloorPPS <= PPS, and a
	// FloorPPS that is a real throttle floor (> 0).
	for name, tier := range map[string]Tier{"polite": polite, "normal": normal, "aggressive": aggressive} {
		if tier.PPS <= 0 {
			t.Errorf("%s.PPS = %v, want > 0", name, tier.PPS)
		}
		if tier.Burst <= 0 {
			t.Errorf("%s.Burst = %v, want > 0", name, tier.Burst)
		}
		if tier.Workers <= 0 {
			t.Errorf("%s.Workers = %v, want > 0", name, tier.Workers)
		}
		if tier.ConnectTimeout <= 0 {
			t.Errorf("%s.ConnectTimeout = %v, want > 0", name, tier.ConnectTimeout)
		}
		if tier.BannerTimeout <= 0 {
			t.Errorf("%s.BannerTimeout = %v, want > 0", name, tier.BannerTimeout)
		}
		if tier.BackoffWindow <= 0 {
			t.Errorf("%s.BackoffWindow = %v, want > 0", name, tier.BackoffWindow)
		}
		if tier.FloorPPS <= 0 {
			t.Errorf("%s.FloorPPS = %v, want > 0", name, tier.FloorPPS)
		}
		if tier.FloorPPS > tier.PPS {
			t.Errorf("%s.FloorPPS = %v exceeds PPS = %v", name, tier.FloorPPS, tier.PPS)
		}
		// Backoff parameters must be sane so Adjust never diverges.
		if !(tier.BackoffFactor > 0 && tier.BackoffFactor < 1) {
			t.Errorf("%s.BackoffFactor = %v, want 0 < factor < 1", name, tier.BackoffFactor)
		}
		if tier.RecoverStep <= 0 {
			t.Errorf("%s.RecoverStep = %v, want > 0", name, tier.RecoverStep)
		}
		if !(tier.StressThreshold > tier.RecoverThreshold) {
			t.Errorf("%s: StressThreshold %v must exceed RecoverThreshold %v",
				name, tier.StressThreshold, tier.RecoverThreshold)
		}
	}

	// Sanity: the resolved tiers actually feed a real limiter without panic.
	_ = rate.NewLimiter(rate.Limit(aggressive.PPS), aggressive.Burst)
}
