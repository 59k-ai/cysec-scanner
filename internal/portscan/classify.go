// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"strconv"
	"strings"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// Deterministic device classification for the port stage (PORT-05, D-08/D-12).
//
// classify() turns the open-port signature, banners, aggregated hints, OUI
// vendor, and the evidence discovery already recorded into a verdict. This phase
// implements only the printer-port rule and a fall-through to "unknown"; the full
// precedence engine lands in a later plan, replacing only this function body. The
// verdict is ALWAYS source- and confidence-labeled (D-08) so a later,
// higher-fidelity stage can override it.
//
// mergeVerdict applies the verdict with the merge-never-replace discipline copied
// from the discovery classifier: it writes INTO the existing classification
// evidence map rather than replacing it, so a routed host keeps its l2_segment
// key and discovery's os_ttl_family / mdns / netbios evidence survives (D-12).

const (
	// Phase-4 verdict labels. The rule names distinguish a port-stage verdict
	// from a discovery-stage carried-evidence record.
	rulePrinterPorts = "port-printer-ports"
	ruleNoMatch      = "port-no-match"

	assetTypePrinter = "printer"
	assetTypeUnknown = "unknown"

	// Printer well-known ports: IPP (631) and HP JetDirect (9100).
	portIPP        = 631
	portJetDirect  = 9100
	printerVerdict = 0.9

	// classifySource labels every Phase-4 verdict so a later higher-fidelity
	// stage knows the value is low-confidence and overridable (D-08).
	classifySource = "port-banner-v1"

	// Evidence keys written by the port classifier.
	evidenceKeyPortSignature   = "port_signature"
	evidenceKeyAssetTypeSource = "asset_type_source"
	evidenceKeyAssetTypeConf   = "asset_type_confidence"
)

// classifyInput bundles everything the classifier reads: the open ports (already
// sorted ascending), the per-port banner text, the single aggregated product/OS
// hint, the OUI vendor (nil when unknown), and the evidence discovery already
// recorded (so the classifier can read os_ttl_family/mdns/netbios without
// re-probing).
type classifyInput struct {
	OpenPorts        []int
	Banners          map[int]string
	ProductHint      string
	OSCue            string
	OUIVendor        *string
	ExistingEvidence map[string]string
}

// verdict is the classifier output, merged into the asset's classification.
type verdict struct {
	AssetType     string
	Confidence    float64
	RuleName      string
	Evidence      map[string]string
	SecurityFlags []string
}

// classify produces a verdict from the open-port signature. This phase matches
// only the printer-port rule and otherwise falls through to "unknown"; the full
// precedence engine replaces this body later. Every verdict records the open-port
// signature plus the D-08 source/confidence provenance so the value is honestly
// low-confidence and overridable.
func classify(in classifyInput) verdict {
	v := verdict{
		Evidence:      map[string]string{},
		SecurityFlags: []string{},
	}

	if containsPort(in.OpenPorts, portIPP) || containsPort(in.OpenPorts, portJetDirect) {
		v.AssetType = assetTypePrinter
		v.Confidence = printerVerdict
		v.RuleName = rulePrinterPorts
	} else {
		v.AssetType = assetTypeUnknown
		v.Confidence = 0.0
		v.RuleName = ruleNoMatch
	}

	v.Evidence[evidenceKeyPortSignature] = joinPorts(in.OpenPorts)
	v.Evidence[evidenceKeyAssetTypeSource] = classifySource
	v.Evidence[evidenceKeyAssetTypeConf] = strconv.FormatFloat(v.Confidence, 'f', -1, 64)
	return v
}

// mergeVerdict merges the verdict into the asset's classification WITHOUT
// replacing it: it nil-guards the classification pointer, initialises the
// evidence map and security-flags slice when absent, writes each verdict evidence
// entry INTO the existing map (preserving discovery's l2_segment/os_ttl_family/
// mdns/netbios keys), appends the verdict's security flags, and sets the asset
// type / confidence / rule name on both the classification and the asset.
func mergeVerdict(a *payload.AssetItem, v verdict) {
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

	for k, val := range v.Evidence {
		c.Evidence[k] = val
	}
	c.SecurityFlags = append(c.SecurityFlags, v.SecurityFlags...)

	c.AssetType = v.AssetType
	c.Confidence = v.Confidence
	c.RuleName = v.RuleName
	a.AssetType = v.AssetType
}

// containsPort reports whether ports contains p.
func containsPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// joinPorts renders a port list as a comma-joined string for the evidence map.
func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}
