// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package osfp

import (
	"math"
	"regexp"
	"testing"
)

// cut mirrors the stage's prefer-unknown confidence cut (0.5, inclusive). The
// engine itself returns a raw confidence; the caller applies the cut, so these
// tests assert the engine's numbers land on the correct side of it.
const cut = 0.5

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestTTLFamilyBoundaries pins the public initial-TTL bucketing at and around
// every boundary, including the out-of-range values that must collapse to "" and
// never crash.
func TestTTLFamilyBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ttl  int
		want string
	}{
		{-1, ""},
		{0, ""},
		{1, familyLinux},
		{64, familyLinux},
		{65, familyWindows},
		{128, familyWindows},
		{129, familyNetwork},
		{255, familyNetwork},
		{256, ""},
		{100000, ""},
	}
	for _, c := range cases {
		if got := ttlFamily(c.ttl); got != c.want {
			t.Errorf("ttlFamily(%d) = %q, want %q", c.ttl, got, c.want)
		}
	}
}

// TestOSGuessTTLAlonePrefersUnknown proves a coarse TTL-only signal scores BELOW
// the cut (spoofable/weak), so the caller degrades it to "unknown".
func TestOSGuessTTLAlonePrefersUnknown(t *testing.T) {
	t.Parallel()
	label, source, conf := Guess(Observation{ReplyTTL: 64}, DefaultSignatures())
	if source != sourceTTL {
		t.Errorf("source = %q, want %q", source, sourceTTL)
	}
	if label != "Linux / Unix" {
		t.Errorf("label = %q, want Linux / Unix", label)
	}
	if conf >= cut {
		t.Errorf("TTL-alone confidence = %v, want < cut %v (must prefer unknown)", conf, cut)
	}
	if !approx(conf, weightTTL) {
		t.Errorf("TTL-alone confidence = %v, want %v", conf, weightTTL)
	}
}

// TestOSGuessTTLPlusBanner proves a corroborating banner OS cue raises a TTL
// guess above the cut, with the higher-fidelity banner source label.
func TestOSGuessTTLPlusBanner(t *testing.T) {
	t.Parallel()
	label, source, conf := Guess(Observation{ReplyTTL: 64, BannerOSCue: "Ubuntu 20.04.1 LTS"}, DefaultSignatures())
	if source != sourceBanner {
		t.Errorf("source = %q, want %q", source, sourceBanner)
	}
	if label != "Linux / Unix" {
		t.Errorf("label = %q, want Linux / Unix", label)
	}
	if conf < cut {
		t.Errorf("TTL+banner confidence = %v, want >= cut %v", conf, cut)
	}
	if !approx(conf, weightTTL+weightBanner) {
		t.Errorf("TTL+banner confidence = %v, want %v", conf, weightTTL+weightBanner)
	}
}

// TestPreferUnknownCutInclusive proves the cut is an inclusive >= comparison: a
// banner-only guess scores exactly the cut (0.5) and so IS emitted, while a
// TTL-only guess scores below it and is suppressed.
func TestPreferUnknownCutInclusive(t *testing.T) {
	t.Parallel()

	// Banner alone (no TTL family) scores exactly the cut.
	_, source, conf := Guess(Observation{BannerOSCue: "Microsoft Windows Server"}, DefaultSignatures())
	if source != sourceBanner {
		t.Errorf("banner-alone source = %q, want %q", source, sourceBanner)
	}
	if !approx(conf, cut) {
		t.Fatalf("banner-alone confidence = %v, want exactly the cut %v", conf, cut)
	}
	if !(conf >= cut) {
		t.Errorf("confidence %v must satisfy the inclusive >= cut %v", conf, cut)
	}

	// TTL alone sits just below the cut.
	_, _, ttlConf := Guess(Observation{ReplyTTL: 128}, DefaultSignatures())
	if ttlConf >= cut {
		t.Errorf("TTL-alone confidence %v must be < cut %v", ttlConf, cut)
	}
}

// TestOSGuessNoSignal proves a host with no TTL and no banner yields an empty
// guess with a zero confidence — the caller nulls os_guess, source and confidence
// together ("unknown").
func TestOSGuessNoSignal(t *testing.T) {
	t.Parallel()
	label, source, conf := Guess(Observation{ReplyTTL: 0, BannerOSCue: ""}, DefaultSignatures())
	if label != "" || source != "" || conf != 0 {
		t.Errorf("no-signal guess = (%q, %q, %v), want all-empty/zero", label, source, conf)
	}
}

// TestOSGuessPhase7SlotsEmpty proves the empty privileged-capture slots
// (TCPWindow/MSS/OptionOrder) contribute nothing and never panic in the
// unprivileged baseline, and that the SAME scorer lifts confidence when a later
// phase DOES populate a stack slot (the plug-in seam).
func TestOSGuessPhase7SlotsEmpty(t *testing.T) {
	t.Parallel()

	// Baseline: TTL present, every stack slot empty -> only the TTL weight scores.
	_, _, conf := Guess(Observation{ReplyTTL: 64, TCPWindow: 0, MSS: 0, OptionOrder: nil}, DefaultSignatures())
	if !approx(conf, weightTTL) {
		t.Errorf("empty stack slots changed the score: got %v, want %v", conf, weightTTL)
	}

	// Seam: a signature that declares a stack observable + an observation that
	// supplies it lifts confidence through the same scorer, no panic.
	sigs := []OSSignature{{
		Label:      "Linux / Unix",
		OSFamily:   familyLinux,
		InitialTTL: []int{64},
		TCPWindow:  []int{64240},
		Weight:     1.0,
	}}
	_, source, stackConf := Guess(Observation{ReplyTTL: 64, TCPWindow: 64240}, sigs)
	if source != sourceStack {
		t.Errorf("stack-slot source = %q, want %q", source, sourceStack)
	}
	if stackConf <= weightTTL {
		t.Errorf("stack slot did not lift confidence: got %v, want > %v", stackConf, weightTTL)
	}
}

// TestOSDBVersionConstant pins the self-authored OS signature DB version format
// (osfp-v1-<ISO-date>) so a signature-table change is paired with a version bump
// (FPRINT-04).
func TestOSDBVersionConstant(t *testing.T) {
	t.Parallel()
	if !regexp.MustCompile(`^osfp-v\d+-\d{4}-\d{2}-\d{2}$`).MatchString(OSSignatureDBVersion) {
		t.Errorf("OSSignatureDBVersion = %q, want osfp-v<N>-<YYYY-MM-DD>", OSSignatureDBVersion)
	}
}
