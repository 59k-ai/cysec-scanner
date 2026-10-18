// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package osfp is a self-authored operating-system signature engine. It scores a
// per-host Observation against a small table of signatures and emits an honest OS
// guess (a family label, a source tag, and a numeric confidence) or nothing when
// the evidence is too weak to prefer over "unknown".
//
// Signature schema (D-03): every OSSignature carries FOUR observable slots —
// InitialTTL and BannerCue (populated this phase from unprivileged signals: the
// reply-TTL family and banner-derived OS cues) plus TCPWindow, MSS and
// OptionOrder (left EMPTY here, the clean plug-in seam a later privileged
// raw-socket capture fills). The scorer consults ONLY the slots an Observation
// populates, so the unprivileged baseline scores TTL + banner while the stack
// slots contribute nothing — and when a later phase fills TCPWindow/MSS/
// OptionOrder the SAME scorer lifts confidence "for free" with no engine change.
//
// Provenance (D-04 / LIC-02): the signature table is SELF-AUTHORED from public
// initial-TTL defaults (64 Linux/Unix/macOS, 128 Windows, 255 many network and
// BSD-style stacks) and own lab observation. It copies NO third-party OS
// fingerprint corpus. Any operator-facing framing of this engine is "nmap-style",
// never a stronger accuracy claim.
package osfp

// OSSignatureDBVersion is the self-authored OS signature database version,
// recorded into scan_metadata on every run (FPRINT-04). Bump it whenever the
// DefaultSignatures table changes so a scan's OS guesses stay reproducible
// against a known signature set.
const OSSignatureDBVersion = "osfp-v1-2026-10-19"

// OS family labels. These mirror the coarse families the discovery TTL bucketing
// produces (see ttlFamily) so a reply-TTL family resolves straight onto a
// signature without a second mapping layer.
const (
	familyLinux   = "linux"
	familyWindows = "windows"
	familyNetwork = "network-device"
)

// OSSignature is one self-authored signature with four observable slots. Only
// InitialTTL and BannerCue are populated this phase; TCPWindow, MSS and
// OptionOrder are declared but left empty as the privileged-capture plug-in seam
// (D-03) — the scorer already consults them, so filling them later needs no
// engine change.
type OSSignature struct {
	// Label is the human-facing OS guess (e.g. "Linux / Unix").
	Label string
	// OSFamily is the coarse family string, one of the family* constants; it is
	// compared against the reply-TTL family the discovery bucketing yields.
	OSFamily string
	// CPE is an optional CPE for the family (empty when not asserted).
	CPE string

	// --- observable slots ---

	// InitialTTL lists the public default initial-TTL values that justify this
	// family (populated now). The scorer buckets each with the SAME ttlFamily
	// function the observation's reply TTL is bucketed with.
	InitialTTL []int
	// BannerCue lists lowercase substrings that, when present in a banner-derived
	// OS cue, corroborate this family (populated now).
	BannerCue []string
	// TCPWindow / MSS / OptionOrder are the privileged-capture slots (empty now —
	// the Phase-of-privileged-capture seam). An Observation leaves them zero/nil
	// this phase, so they contribute nothing and never panic.
	TCPWindow   []int
	MSS         []int
	OptionOrder []string

	// Weight scales this signature's score (a tunable; 1.0 for the baseline
	// table). It lets a future signature be down-weighted without touching the
	// scorer.
	Weight float64
}

// Observation is the per-host evidence the engine scores. ReplyTTL and
// BannerOSCue are populated this phase from the accumulator (the discovery
// reply-TTL family and a banner-derived OS cue); TCPWindow, MSS and OptionOrder
// are the privileged-capture inputs, zero/nil in the unprivileged baseline.
type Observation struct {
	// ReplyTTL is the host's observed reply TTL. The unprivileged stage supplies
	// the public initial-TTL default for the coarse family discovery recorded (the
	// raw reply TTL is not carried on the wire); a later privileged capture
	// supplies the real observed TTL. A value <= 0 means "no TTL signal".
	ReplyTTL int
	// BannerOSCue is a banner-derived OS cue (e.g. a Recog os.family such as
	// "Windows" or "Linux"), or "" when no banner named an OS.
	BannerOSCue string
	// TCPWindow / MSS / OptionOrder are the privileged-capture observables (0/nil
	// this phase). When populated by a later phase the scorer picks them up.
	TCPWindow   int
	MSS         int
	OptionOrder []string
}

// DefaultSignatures returns the self-authored baseline signature table, authored
// from public initial-TTL defaults and own lab observation only (no third-party
// OS fingerprint data — D-04 / LIC-02). The BannerCue lists are deliberately
// OS-indicative substrings, not generic service names, so a banner only
// corroborates a family when it actually names an operating system.
func DefaultSignatures() []OSSignature {
	return []OSSignature{
		{
			Label:      "Linux / Unix",
			OSFamily:   familyLinux,
			InitialTTL: []int{64},
			BannerCue:  []string{"linux", "ubuntu", "debian", "centos", "red hat", "redhat", "fedora", "unix"},
			Weight:     1.0,
		},
		{
			Label:      "Windows",
			OSFamily:   familyWindows,
			InitialTTL: []int{128},
			BannerCue:  []string{"windows", "win32", "win64", "microsoft"},
			Weight:     1.0,
		},
		{
			Label:      "Network device",
			OSFamily:   familyNetwork,
			InitialTTL: []int{255},
			BannerCue:  []string{"routeros", "mikrotik", "fortios", "cisco ios", "ios-xe", "junos", "openwrt"},
			Weight:     1.0,
		},
	}
}

// ttlFamily maps a reply TTL onto a coarse OS family using the SAME public
// initial-TTL brackets the discovery stage uses (<=0 none, <=64 linux, <=128
// windows, <=255 network device, >255 none). It is re-expressed here (not
// imported) because the discovery helper is unexported; the boundary values are
// identical by design so a reply-TTL family resolves consistently across stages.
// An absent (<=0) or out-of-range (>255) TTL collapses to "" rather than
// crashing.
func ttlFamily(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return familyLinux
	case ttl <= 128:
		return familyWindows
	case ttl <= 255:
		return familyNetwork
	default:
		return ""
	}
}

// TTLForFamily returns the public default initial TTL for a coarse family, so the
// unprivileged stage (which has only the discovery family string, not the raw
// reply TTL) can supply a representative TTL to the TTL slot. It is the inverse of
// ttlFamily over the public defaults; an unknown family yields 0 ("no TTL
// signal").
func TTLForFamily(family string) int {
	switch family {
	case familyLinux:
		return 64
	case familyWindows:
		return 128
	case familyNetwork:
		return 255
	default:
		return 0
	}
}
