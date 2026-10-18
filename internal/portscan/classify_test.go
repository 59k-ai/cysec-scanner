// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"reflect"
	"testing"
)

// validAssetTypes is the closed asset_type enum the cloud ingest accepts; every
// verdict MUST land inside it (a classifier that invents a seventh value would be
// silently dropped at the boundary).
var validAssetTypes = map[string]bool{
	"server":      true,
	"workstation": true,
	"printer":     true,
	"iot":         true,
	"network":     true,
	"unknown":     true,
}

// TestClassify exercises the full deterministic 8-rule precedence engine: every
// rule's firing case, the precedence relationships between rules (Rule 0 beats
// the port/vendor rules; the broad-module-vendor-with-no-port fall-through), the
// fall-through to unknown, the D-08 source/confidence provenance, and that every
// verdict stays inside the 6-value enum.
func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		in       classifyInput
		wantType string
		wantConf float64
		wantRule string
	}{
		{
			name:     "rule0 banner router beats everything",
			in:       classifyInput{OpenPorts: []int{80, 631}, ProductHint: "router"},
			wantType: "network", wantConf: 0.95, wantRule: "banner-http-router",
		},
		{
			name:     "rule0 banner camera",
			in:       classifyInput{OpenPorts: []int{80}, ProductHint: "camera"},
			wantType: "iot", wantConf: 0.9, wantRule: "banner-http-camera",
		},
		{
			name:     "rule0 banner echo",
			in:       classifyInput{OpenPorts: []int{80}, ProductHint: "echo"},
			wantType: "iot", wantConf: 0.9, wantRule: "banner-http-echo",
		},
		{
			name:     "rule0 banner printer",
			in:       classifyInput{OpenPorts: []int{80}, ProductHint: "printer"},
			wantType: "printer", wantConf: 0.95, wantRule: "banner-http-printer",
		},
		{
			name:     "rule0 banner nas",
			in:       classifyInput{OpenPorts: []int{80}, ProductHint: "nas"},
			wantType: "server", wantConf: 0.85, wantRule: "banner-http-nas",
		},
		{
			name:     "rule0 banner openwrt",
			in:       classifyInput{OpenPorts: []int{80}, ProductHint: "openwrt"},
			wantType: "network", wantConf: 0.85, wantRule: "banner-http-openwrt",
		},
		{
			name:     "rule1 printer port 631",
			in:       classifyInput{OpenPorts: []int{631}},
			wantType: "printer", wantConf: 0.9, wantRule: "port-printer-ports",
		},
		{
			name:     "rule1 printer port 9100",
			in:       classifyInput{OpenPorts: []int{9100, 80}},
			wantType: "printer", wantConf: 0.9, wantRule: "port-printer-ports",
		},
		{
			name:     "rule2 network vendor + snmp",
			in:       classifyInput{OpenPorts: []int{161}, OUIVendor: strPtr("Cisco Systems, Inc")},
			wantType: "network", wantConf: 0.85, wantRule: "port-network-vendor-snmp",
		},
		{
			name:     "rule2 network vendor + ssh",
			in:       classifyInput{OpenPorts: []int{22}, OUIVendor: strPtr("MikroTikls SIA")},
			wantType: "network", wantConf: 0.85, wantRule: "port-network-vendor-snmp",
		},
		{
			name:     "rule3 iot vendor, few ports",
			in:       classifyInput{OpenPorts: []int{80, 443}, OUIVendor: strPtr("Espressif Inc.")},
			wantType: "iot", wantConf: 0.8, wantRule: "port-iot-vendor",
		},
		{
			name:     "rule3 broad-module vendor with one port fires",
			in:       classifyInput{OpenPorts: []int{80}, OUIVendor: strPtr("Realtek Semiconductor Corp.")},
			wantType: "iot", wantConf: 0.8, wantRule: "port-iot-vendor",
		},
		{
			name:     "rule3 broad-module vendor with zero ports falls through",
			in:       classifyInput{OpenPorts: []int{}, OUIVendor: strPtr("Realtek Semiconductor Corp.")},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match",
		},
		{
			name:     "rule4 server ssh+web+db",
			in:       classifyInput{OpenPorts: []int{22, 443, 5432}},
			wantType: "server", wantConf: 0.9, wantRule: "port-server-ssh-web-db",
		},
		{
			name:     "rule5 windows server fingerprint",
			in:       classifyInput{OpenPorts: []int{445}, ExistingEvidence: map[string]string{"os_ttl_family": "windows"}, OSCue: "server"},
			wantType: "server", wantConf: 0.85, wantRule: "fp-server-windows",
		},
		{
			name:     "rule6 windows workstation smb+rdp",
			in:       classifyInput{OpenPorts: []int{445, 3389}, ExistingEvidence: map[string]string{"os_ttl_family": "windows"}},
			wantType: "workstation", wantConf: 0.8, wantRule: "fp-workstation-windows",
		},
		{
			name:     "rule7 linux workstation ssh no db",
			in:       classifyInput{OpenPorts: []int{22}, ExistingEvidence: map[string]string{"os_ttl_family": "linux"}},
			wantType: "workstation", wantConf: 0.6, wantRule: "fp-workstation-linux",
		},
		{
			name:     "rule7 excluded when a db port is open",
			in:       classifyInput{OpenPorts: []int{22, 5432}, ExistingEvidence: map[string]string{"os_ttl_family": "linux"}},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match",
		},
		{
			name:     "linux os cue from banner fires rule7",
			in:       classifyInput{OpenPorts: []int{22}, OSCue: "linux"},
			wantType: "workstation", wantConf: 0.6, wantRule: "fp-workstation-linux",
		},
		{
			name:     "fall-through unknown",
			in:       classifyInput{OpenPorts: []int{8080}},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match",
		},
		{
			name:     "no signal at all",
			in:       classifyInput{OpenPorts: []int{}},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classify(tc.in)
			if v.AssetType != tc.wantType {
				t.Errorf("AssetType = %q, want %q", v.AssetType, tc.wantType)
			}
			if v.Confidence != tc.wantConf {
				t.Errorf("Confidence = %v, want %v", v.Confidence, tc.wantConf)
			}
			if v.RuleName != tc.wantRule {
				t.Errorf("RuleName = %q, want %q", v.RuleName, tc.wantRule)
			}
			if !validAssetTypes[v.AssetType] {
				t.Errorf("AssetType %q is outside the 6-value enum", v.AssetType)
			}
			// D-08: every verdict is source-labeled and graded on the evidence map.
			if v.Evidence["asset_type_source"] != "port-banner-v1" {
				t.Errorf("asset_type_source = %q, want port-banner-v1", v.Evidence["asset_type_source"])
			}
			if v.Evidence["asset_type_confidence"] == "" {
				t.Errorf("asset_type_confidence missing from evidence map")
			}
		})
	}
}

// TestClassifyDeterministic asserts the classifier is a pure function: the same
// input yields a byte-identical verdict (same asset_type, confidence, rule_name,
// and evidence map), so the pipeline is reproducible (PORT-05 determinism edge).
func TestClassifyDeterministic(t *testing.T) {
	in := classifyInput{
		OpenPorts:        []int{22, 443, 5432},
		OUIVendor:        strPtr("Dell Inc."),
		ExistingEvidence: map[string]string{"os_ttl_family": "linux", "l2_segment": "routed"},
		OSCue:            "linux",
		ProductHint:      "",
	}
	a := classify(in)
	b := classify(in)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("classify is not deterministic:\n first = %+v\nsecond = %+v", a, b)
	}
}

// TestClassifyPortSignatureSorted asserts equal port inputs supplied in different
// orders (and with a duplicate) collide to the same verdict via a sorted, deduped
// port signature (PORT-05 adjacency edge).
func TestClassifyPortSignatureSorted(t *testing.T) {
	a := classify(classifyInput{OpenPorts: []int{443, 22, 5432}})
	b := classify(classifyInput{OpenPorts: []int{22, 5432, 443, 22}})
	if a.Evidence["port_signature"] != b.Evidence["port_signature"] {
		t.Errorf("port_signature not order/dup-stable: %q vs %q",
			a.Evidence["port_signature"], b.Evidence["port_signature"])
	}
	if a.Evidence["port_signature"] != "22,443,5432" {
		t.Errorf("port_signature = %q, want 22,443,5432", a.Evidence["port_signature"])
	}
}
