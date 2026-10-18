// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package osfp

import "strings"

// Source labels the engine stamps so an auditor can tell which observable slots
// produced an OS guess. osfp-ttl-v1 is a TTL-only guess (weak, below the cut on
// its own), osfp-banner-v1 is raised by a banner OS cue, and osfp-stack-v1 is the
// privileged-capture tier (TCPWindow/MSS/OptionOrder) a later phase fills.
const (
	sourceTTL    = "osfp-ttl-v1"
	sourceBanner = "osfp-banner-v1"
	sourceStack  = "osfp-stack-v1"
)

// Per-slot weights. They are calibrated so a coarse, attacker-spoofable TTL
// signal alone scores BELOW the prefer-unknown cut (0.5) — a reply TTL is trivial
// to forge, so it must degrade to "unknown" rather than leak as authoritative —
// while a banner OS cue (harder to spoof, names the OS) is a strong signal that
// on its own reaches the cut and, with a corroborating TTL, clears it
// comfortably. The privileged-capture slots score highest because a raw-socket
// stack match is the least spoofable signal. Values are reversible tunables.
const (
	weightTTL         = 0.30 // TTL alone: 0.30 < cut -> unknown
	weightBanner      = 0.50 // banner alone: 0.50 == cut (inclusive) -> emitted
	weightTCPWindow   = 0.40 // privileged capture (seam)
	weightMSS         = 0.20 // privileged capture (seam)
	weightOptionOrder = 0.30 // privileged capture (seam)
)

// Guess scores obs against each signature and returns the best match's family
// label, a source tag, and a numeric confidence in [0,1]. It consults ONLY the
// slots obs populates, so the unprivileged baseline (reply TTL + banner cue)
// scores the TTL and banner slots while the empty privileged-capture slots
// contribute nothing — and a later phase that fills TCPWindow/MSS/OptionOrder
// lifts confidence through the SAME scorer with no change here.
//
// When no slot of any signature matches (no TTL family, no banner cue, no stack
// observables) it returns ("", "", 0) so the caller emits no OS guess ("unknown")
// with the source and confidence null together. Guess never panics: empty/zero
// observable slots are simply skipped.
func Guess(obs Observation, sigs []OSSignature) (label, source string, confidence float64) {
	best := 0.0
	for _, sig := range sigs {
		score, src := scoreSignature(obs, sig)
		if score > best {
			best = score
			label = sig.Label
			source = src
			confidence = score
		}
	}
	if best <= 0 {
		return "", "", 0
	}
	return label, source, confidence
}

// scoreSignature returns the additive, [0,1]-capped score of obs against one
// signature and the source tag of the highest-fidelity slot that contributed.
// Each slot is consulted only when obs populates it, so empty slots neither add
// score nor panic.
func scoreSignature(obs Observation, sig OSSignature) (float64, string) {
	score := 0.0
	source := ""

	if ttlSlotHit(obs, sig) {
		score += weightTTL
		source = sourceTTL
	}
	if bannerSlotHit(obs, sig) {
		score += weightBanner
		source = sourceBanner // banner is higher-fidelity than TTL
	}
	// Privileged-capture slots (the plug-in seam). An Observation leaves these
	// zero/nil this phase, so the guards short-circuit and nothing is added.
	if obs.TCPWindow != 0 && containsInt(sig.TCPWindow, obs.TCPWindow) {
		score += weightTCPWindow
		source = sourceStack
	}
	if obs.MSS != 0 && containsInt(sig.MSS, obs.MSS) {
		score += weightMSS
		source = sourceStack
	}
	if len(obs.OptionOrder) > 0 && equalStrings(sig.OptionOrder, obs.OptionOrder) {
		score += weightOptionOrder
		source = sourceStack
	}

	if source == "" {
		return 0, ""
	}
	if w := sig.Weight; w > 0 {
		score *= w
	}
	if score > 1.0 {
		score = 1.0
	}
	return score, source
}

// ttlSlotHit reports whether obs's reply-TTL family matches one of the
// signature's public initial-TTL defaults, bucketed by the SAME ttlFamily
// function on both sides (so a reply TTL and a public default collapse to the
// same coarse family). A missing or out-of-range TTL never hits.
func ttlSlotHit(obs Observation, sig OSSignature) bool {
	fam := ttlFamily(obs.ReplyTTL)
	if fam == "" {
		return false
	}
	for _, init := range sig.InitialTTL {
		if ttlFamily(init) == fam {
			return true
		}
	}
	return false
}

// bannerSlotHit reports whether obs's banner-derived OS cue contains one of the
// signature's OS-indicative substrings (case-insensitive). An empty cue never
// hits.
func bannerSlotHit(obs Observation, sig OSSignature) bool {
	if obs.BannerOSCue == "" {
		return false
	}
	cue := strings.ToLower(obs.BannerOSCue)
	for _, b := range sig.BannerCue {
		if b != "" && strings.Contains(cue, strings.ToLower(b)) {
			return true
		}
	}
	return false
}

// containsInt reports whether xs contains v.
func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// equalStrings reports whether a and b are the same length and element-wise
// equal (order-sensitive, as a TCP option order is).
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
