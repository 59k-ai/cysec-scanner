// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package discovery

import "github.com/59k-ai/cysec-scanner/payload"

// Classification-evidence shaping (DISC-05). This enrichment runs LAST in the
// discovery run — after Layer-2 and hostname enrichment — and ASSEMBLES each
// asset's classification_evidence by READING the signals the earlier passes
// already recorded on the internal host record. It re-probes nothing:
//   - mac_vendor      ← the OUI vendor assigned during L2 enrichment
//   - os_ttl_family   ← the coarse family derived from the sweep's reply TTL
//   - mdns / netbios  ← the per-resolver hit flags set during hostname
//                       enrichment (a presence entry appears ONLY when its flag
//                       is true — an absent flag means the signal is simply not
//                       there, never a fabricated false one)
//
// The asset_type stays "unknown" this phase (D-02): the full deterministic
// rule engine needs open-port data that arrives in a later phase, so discovery
// carries the evidence STRUCTURE without fabricating a confident verdict. Every
// signal is evidence only and feeds no compliance decision.
const (
	// assetTypeUnknown is the deferred asset_type carried this phase (D-02).
	assetTypeUnknown = "unknown"
	// discoveryRuleName labels the evidence as discovery-stage output so a later
	// phase can tell a carried-evidence record from a real rule-engine verdict.
	discoveryRuleName = "discovery-evidence-v1"
	// classifyConfidenceLow marks the carried evidence as a low-confidence hint,
	// not a verdict: a spoofable TTL/vendor must never read as a confident type.
	classifyConfidenceLow = 0.1

	// Evidence map keys for the signals assembled this phase.
	evidenceKeyMACVendor   = "mac_vendor"
	evidenceKeyOSTTLFamily = "os_ttl_family"
	evidenceKeyMDNS        = "mdns"
	evidenceKeyNetBIOS     = "netbios"
	// evidenceValuePresent is the value for a presence-only signal (mdns/netbios):
	// the flag answered, so the signal is recorded as observed.
	evidenceValuePresent = "present"
)

// ttlFamily maps a best-effort reply TTL onto a coarse OS family. The brackets
// are the common initial-TTL defaults (≤64 linux/unix, ≤128 windows, ≤255
// network device). The result is a LOW-CONFIDENCE hint only — a reply TTL is
// attacker-spoofable (Pitfall 7) — and an absent (≤0) or out-of-range (>255)
// TTL collapses to "" rather than crashing.
func ttlFamily(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return "linux"
	case ttl <= 128:
		return "windows"
	case ttl <= 255:
		return "network-device"
	default:
		return ""
	}
}

// classifyAsset assembles the asset's classification_evidence from the signals
// the earlier passes recorded on e, MERGING into any pre-existing classification
// so a routed host's evidence["l2_segment"]="routed" (set during L2 enrichment)
// is preserved rather than overwritten. It sets asset_type to "unknown" on BOTH
// the asset and the classification (D-02), fills the TTL-derived OS hint, and
// guarantees evidence and security_flags are non-nil (so no required container
// ever marshals as JSON null — Pitfall 3). Managed/InternetFacing are left
// untouched (false from buildAsset): discovery never claims LAN exposure.
func classifyAsset(a *payload.AssetItem, e hostEntry) {
	if a.Classification == nil {
		a.Classification = &payload.ClassificationEvidence{}
	}
	c := a.Classification
	if c.Evidence == nil {
		c.Evidence = map[string]string{}
	}
	if c.SecurityFlags == nil {
		c.SecurityFlags = []string{}
	}

	// MERGE signals into the existing evidence map — never replace it, so a
	// routed host keeps its l2_segment key.
	if e.macVendor != nil && *e.macVendor != "" {
		c.Evidence[evidenceKeyMACVendor] = *e.macVendor
	}
	if fam := ttlFamily(e.ttl); fam != "" {
		c.Evidence[evidenceKeyOSTTLFamily] = fam
		a.OSFingerprintHint = fam
	}
	if e.mdnsHit {
		c.Evidence[evidenceKeyMDNS] = evidenceValuePresent
	}
	if e.netbiosHit {
		c.Evidence[evidenceKeyNetBIOS] = evidenceValuePresent
	}

	c.AssetType = assetTypeUnknown
	c.Confidence = classifyConfidenceLow
	c.RuleName = discoveryRuleName
	a.AssetType = assetTypeUnknown
}
