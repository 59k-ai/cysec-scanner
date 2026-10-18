// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"time"

	"golang.org/x/time/rate"
)

// Timing contract for the port stage (PORT-02/PORT-03, D-03/D-04/D-05).
//
// A Tier bundles the full load-shaping budget for one scan: the scan-wide
// packets-per-second ceiling (one shared token bucket, never per host), the
// bounded worker-pool size, the per-connect and per-banner deadlines, and the
// adaptive-backoff parameters. A single conservative "polite" tier is resolved
// this phase; the other named tiers only fill in different VALUES for these same
// fields later — no field is added after this phase, so the adaptive-backoff
// hook never has to re-touch the orchestrator.

// Tier is the resolved load-shaping budget for one scan. Every field is declared
// now; later tiers (normal/aggressive) only set different values.
//
//   - PPS is the scan-wide ceiling fed to the one shared rate.Limiter (D-04).
//   - Burst / Workers bound the token-bucket burst and the in-flight socket count.
//   - ConnectTimeout bounds each dial; BannerTimeout bounds each banner read.
//   - FloorPPS is the lowest rate the adaptive backoff may throttle down to.
//   - StressThreshold / RecoverThreshold are the timeout+error ratio bands that
//     trigger easing off vs. recovering (D-05).
//   - BackoffFactor multiplies the live rate when stressed; RecoverStep is the
//     additive packets-per-second nudge back up when the network is calm.
//   - BackoffWindow is how many recent outcomes the sliding window keeps.
type Tier struct {
	PPS              float64
	Burst            int
	Workers          int
	ConnectTimeout   time.Duration
	BannerTimeout    time.Duration
	FloorPPS         float64
	StressThreshold  float64
	RecoverThreshold float64
	BackoffFactor    float64
	RecoverStep      float64
	BackoffWindow    int
}

// probeOutcome grades a single connect attempt so the adaptive backoff can tell a
// healthy network apart from a stressed one:
//   - outcomeOpen: the TCP handshake completed (the port is open).
//   - outcomeRefused: a fast RST — the host is reachable and healthy, the port is
//     simply closed; this is NOT a stress signal.
//   - outcomeTimeout: no response within the deadline — filtered or ambiguous,
//     the primary "are we pushing too hard?" signal.
//   - outcomeError: any other failure (reset mid-connect, unreachable, local
//     resource exhaustion) — the genuine-stress bucket.
type probeOutcome int

const (
	outcomeOpen probeOutcome = iota
	outcomeRefused
	outcomeTimeout
	outcomeError
)

// defaultBackoffWindow is the sliding-window size used when a tier declares a
// non-positive BackoffWindow, so the window is always well-formed.
const defaultBackoffWindow = 50

// outcomeWindow is a fixed-size sliding ring of the most recent probe outcomes.
// Writing past capacity overwrites the oldest entry, so the window rolls forward
// inherently (no separate reset). It is maintained by Run under the results mutex
// and read by Tier.Adjust; keeping the type and its methods here lets the
// adaptive-backoff tier logic read it without re-touching the orchestrator.
type outcomeWindow struct {
	buf  []probeOutcome
	cap  int
	size int
	next int
}

// newOutcomeWindow returns a window holding the most recent capacity outcomes,
// falling back to defaultBackoffWindow when capacity is non-positive.
func newOutcomeWindow(capacity int) *outcomeWindow {
	if capacity <= 0 {
		capacity = defaultBackoffWindow
	}
	return &outcomeWindow{buf: make([]probeOutcome, capacity), cap: capacity}
}

// record appends one outcome, overwriting the oldest once the window is full.
func (w *outcomeWindow) record(o probeOutcome) {
	w.buf[w.next] = o
	w.next = (w.next + 1) % w.cap
	if w.size < w.cap {
		w.size++
	}
}

// counts tallies the outcomes currently in the window. total is the number of
// entries held (<= capacity), so a caller can compute stress ratios.
func (w *outcomeWindow) counts() (open, refused, timeout, errored, total int) {
	for i := 0; i < w.size; i++ {
		switch w.buf[i] {
		case outcomeOpen:
			open++
		case outcomeRefused:
			refused++
		case outcomeTimeout:
			timeout++
		case outcomeError:
			errored++
		}
	}
	return open, refused, timeout, errored, w.size
}

// ResolveTier maps an operator-facing timing name onto a resolved Tier. This
// phase ships a single conservative "polite" tier and returns it for ANY input
// (the normal/aggressive tiers only add different VALUES for these same fields
// later). The numeric values below are ASSUMED conservative defaults pending
// operator confirmation — a low-hundreds PPS ceiling, a small worker pool, and
// second-scale deadlines keep a mid-market LAN safe by default (D-03/D-04).
func ResolveTier(name string) Tier {
	_ = name // every name resolves to polite this phase
	return politeTier()
}

// politeTier is the conservative default: a low-hundreds PPS ceiling, a small
// in-flight socket bound, second-scale deadlines, and gentle backoff parameters.
func politeTier() Tier {
	return Tier{
		PPS:              100,
		Burst:            16,
		Workers:          16,
		ConnectTimeout:   1 * time.Second,
		BannerTimeout:    2 * time.Second,
		FloorPPS:         20,
		StressThreshold:  0.30,
		RecoverThreshold: 0.05,
		BackoffFactor:    0.5,
		RecoverStep:      10,
		BackoffWindow:    50,
	}
}

// Adjust is the adaptive throttle-down hook (D-05). It reads the sliding window
// of recent outcomes and eases the live limiter rate down under stress, then
// recovers slowly when the network calms. It is a documented no-op stub this
// phase; the orchestrator already feeds the window and calls this hook on every
// probe, so the adaptive logic lands here later without touching the
// orchestrator.
func (t Tier) Adjust(l *rate.Limiter, w *outcomeWindow) {
	_ = l
	_ = w
}
