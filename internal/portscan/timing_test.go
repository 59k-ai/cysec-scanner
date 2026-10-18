// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"testing"
	"time"

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

// backoffTier is a compact, well-formed tier used by the adaptive-backoff tests:
// a short BackoffWindow so a window fills quickly, and round numbers so the
// throttle-down (x0.5, floor 20) and recovery (+10, ceiling 100) paths land on
// exactly representable values.
func backoffTier() Tier {
	return Tier{
		PPS:              100,
		Burst:            10,
		Workers:          10,
		ConnectTimeout:   time.Second,
		BannerTimeout:    time.Second,
		FloorPPS:         20,
		StressThreshold:  0.30,
		RecoverThreshold: 0.05,
		BackoffFactor:    0.5,
		RecoverStep:      10,
		BackoffWindow:    10,
	}
}

// fillWindow records n copies of o into w (helper for building a known window).
func fillWindow(w *outcomeWindow, o probeOutcome, n int) {
	for i := 0; i < n; i++ {
		w.record(o)
	}
}

// TestAdaptiveBackoff pins the PORT-02 / D-05 adaptive throttle-down contract:
// the genuine-stress signal is the ERRORED ratio (resets / resource exhaustion /
// unreachable), NEVER ordinary filtered-port timeouts.
func TestAdaptiveBackoff(t *testing.T) {
	tier := backoffTier()

	// --- Insufficient window: below the sample threshold, nothing changes. ---
	t.Run("insufficient_window_unchanged", func(t *testing.T) {
		l := rate.NewLimiter(rate.Limit(tier.PPS), tier.Burst)
		w := newOutcomeWindow(tier.BackoffWindow)
		// One below the window: a full window of errors would otherwise halve it.
		fillWindow(w, outcomeError, tier.BackoffWindow-1)
		tier.Adjust(l, w)
		if got := float64(l.Limit()); got != tier.PPS {
			t.Fatalf("below window (total=%d<%d) limit changed to %v, want unchanged %v",
				tier.BackoffWindow-1, tier.BackoffWindow, got, tier.PPS)
		}
		// Exactly at the window boundary: now it may act.
		w.record(outcomeError)
		tier.Adjust(l, w)
		if got := float64(l.Limit()); got != tier.PPS*tier.BackoffFactor {
			t.Fatalf("at window boundary limit = %v, want throttled to %v",
				got, tier.PPS*tier.BackoffFactor)
		}
	})

	// --- Errored stress: limit drops by the factor and clamps at the floor. ---
	t.Run("errored_stress_drops_to_floor", func(t *testing.T) {
		l := rate.NewLimiter(rate.Limit(tier.PPS), tier.Burst)
		w := newOutcomeWindow(tier.BackoffWindow)
		fillWindow(w, outcomeError, tier.BackoffWindow) // ratio 1.0 >= 0.30

		want := []float64{50, 25, 20, 20} // 100*0.5, *0.5, clamp at 20, stays
		for i, exp := range want {
			tier.Adjust(l, w)
			if got := float64(l.Limit()); got != exp {
				t.Fatalf("stress step %d: limit = %v, want %v (monotonic down, clamp at floor)", i, got, exp)
			}
		}
		if got := float64(l.Limit()); got < tier.FloorPPS {
			t.Fatalf("limit %v dropped below FloorPPS %v", got, tier.FloorPPS)
		}
	})

	// --- Calm: limit rises additively and clamps at the tier ceiling. ---
	t.Run("calm_recovers_to_ceiling", func(t *testing.T) {
		l := rate.NewLimiter(rate.Limit(tier.FloorPPS), tier.Burst) // start low
		w := newOutcomeWindow(tier.BackoffWindow)
		// A reachable, quiet network: half open, half refused -> zero errored.
		fillWindow(w, outcomeOpen, tier.BackoffWindow/2)
		fillWindow(w, outcomeRefused, tier.BackoffWindow/2)

		want := []float64{30, 40, 50, 60, 70, 80, 90, 100, 100} // +10 each, clamp 100
		for i, exp := range want {
			tier.Adjust(l, w)
			if got := float64(l.Limit()); got != exp {
				t.Fatalf("calm step %d: limit = %v, want %v (monotonic up, clamp at ceiling)", i, got, exp)
			}
		}
		if got := float64(l.Limit()); got > tier.PPS {
			t.Fatalf("limit %v rose above tier PPS ceiling %v", got, tier.PPS)
		}
	})

	// --- CRITICAL INVARIANT: a full window of pure filtered-port timeouts with
	// zero errored outcomes and reachability proof (a refused present) is HEALTHY
	// and must NOT be throttled down — ordinary scans of filtered hosts are not
	// penalized. (checker key-link) ---
	t.Run("pure_filtered_timeouts_not_throttled", func(t *testing.T) {
		l := rate.NewLimiter(rate.Limit(tier.PPS), tier.Burst)
		w := newOutcomeWindow(tier.BackoffWindow)
		// Reachable host, filtered ports: timeouts dominate, one refused proves
		// reachability, ZERO errored.
		fillWindow(w, outcomeTimeout, tier.BackoffWindow-1)
		w.record(outcomeRefused)
		_, _, timeout, errored, total := w.counts()
		if errored != 0 || timeout == 0 || total != tier.BackoffWindow {
			t.Fatalf("precondition: want zero errored with timeouts filling the window, got timeout=%d errored=%d total=%d",
				timeout, errored, total)
		}
		tier.Adjust(l, w)
		if got := float64(l.Limit()); got < tier.PPS {
			t.Fatalf("healthy filtered-timeout window throttled limit down to %v (from %v) — ordinary scans must not throttle",
				got, tier.PPS)
		}
	})

	// --- Mid-band (above recover, below stress): limit holds steady. ---
	t.Run("mid_band_holds", func(t *testing.T) {
		l := rate.NewLimiter(rate.Limit(tier.PPS), tier.Burst)
		w := newOutcomeWindow(tier.BackoffWindow)
		// errored ratio = 0.10: above RecoverThreshold (0.05), below Stress (0.30).
		fillWindow(w, outcomeError, 1)
		fillWindow(w, outcomeRefused, tier.BackoffWindow-1)
		tier.Adjust(l, w)
		if got := float64(l.Limit()); got != tier.PPS {
			t.Fatalf("mid-band errored ratio changed limit to %v, want held at %v", got, tier.PPS)
		}
	})
}
