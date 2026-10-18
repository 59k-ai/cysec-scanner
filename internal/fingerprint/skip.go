// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import "strings"

// Fragile-device skip gate (FPRINT-05, D-10). Some gear — printers, IoT/embedded
// devices, and network infrastructure — misbehaves or falls over under intrusive
// OS stack probing, so it is excluded from that probing by default. This stage is
// PASSIVE (the TTL/banner os_guess from the engine is NOT intrusive and is never
// gated), so there is no intrusive probe to suppress yet; the gate is built here
// as a pure predicate so the later privileged stage that DOES stack-probe consults
// the SAME decision. The operator can override with --probe-fragile.
//
// The gate keys on the REAL asset_type enum {printer, iot, network} — there is no
// "camera" or "ot" value: a camera classifies as iot and a router/OT device as
// network in the port stage, so the printer/IoT/OT intent of the requirement is
// covered by these three enum members — OR on an OUI vendor match against the
// networking-gear / IoT-maker lists.

// fragileAssetTypes is the set of asset_type verdicts that mark a host as fragile
// gear excluded from intrusive probing. The values are the real port-stage enum
// members (printer / iot / network); camera->iot and router/OT->network mean this
// set covers the requirement's printer/IoT/OT intent.
var fragileAssetTypes = map[string]bool{
	"printer": true,
	"iot":     true,
	"network": true,
}

// networkVendors mirrors the port-stage networking-gear OUI substrings verbatim
// (the same Phase-4 dataset, re-expressed here because the port-stage symbol is
// unexported — keep the two copies in lockstep; do NOT fork the list).
var networkVendors = []string{
	"cisco", "juniper", "mikrotik", "ubiquiti", "aruba",
	"hewlett packard enterprise", "fortinet", "extreme networks",
	"tp-link", "tp link", "tenda", "huawei", "zte", "fiberhome",
	"netgear", "asus", "d-link", " technicolor", "routerboard", "avm",
}

// iotVendors mirrors the port-stage consumer-IoT / embedded-module OUI substrings
// verbatim (the same Phase-4 dataset, re-expressed here because the port-stage
// symbol is unexported — keep the two copies in lockstep; do NOT fork the list).
var iotVendors = []string{
	"philips lighting", "signify", "hue", "nest", "sonos", "ring", "ecobee",
	"amazon technologies", "google", "tuya", "lg innotek", "ampak", "espressif",
	"realtek", "mediatek", "raspberry pi", "silicon labs", "nordic semiconductor",
	"silicondust", "shenzhen",
}

// shouldSkipIntrusiveProbe reports whether intrusive OS stack probing of a host
// should be skipped. The --probe-fragile override is checked FIRST and wins over
// any fragile classification: when probeFragile is true the function always
// returns false. Otherwise a host is skipped when its asset_type is a fragile
// enum member OR its OUI vendor matches the networking-gear / IoT-maker lists. A
// host with no fragile verdict and no OUI match is not fragile (returns false —
// probing allowed). ouiVendor is expected pre-lowercased (the port stage stores it
// lowercased in the classification evidence).
func shouldSkipIntrusiveProbe(assetType, ouiVendor string, probeFragile bool) bool {
	if probeFragile {
		// Operator escape hatch (mirrors --ports): the override wins outright, even
		// for a host that is both fragile AND carries a strong OS signal.
		return false
	}
	if fragileAssetTypes[assetType] {
		return true
	}
	return matchesVendor(ouiVendor, networkVendors) || matchesVendor(ouiVendor, iotVendors)
}

// matchesVendor reports whether the (already-lowercased) OUI vendor contains any
// of the lowercased substrings in list. Mirrors the port-stage helper.
func matchesVendor(vendor string, list []string) bool {
	if vendor == "" {
		return false
	}
	for _, s := range list {
		if strings.Contains(vendor, s) {
			return true
		}
	}
	return false
}
