// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"reflect"
	"testing"

	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
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

// TestClassify exercises the full deterministic precedence engine: every
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
			name:     "rule7 unix ssh server, ssh only",
			in:       classifyInput{OpenPorts: []int{22}, ExistingEvidence: map[string]string{"os_ttl_family": "unix-like"}},
			wantType: "server", wantConf: 0.6, wantRule: "fp-server-unix-ssh",
		},
		{
			name:     "rule7 excluded when a db port is open",
			in:       classifyInput{OpenPorts: []int{22, 5432}, ExistingEvidence: map[string]string{"os_ttl_family": "unix-like"}},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match",
		},
		{
			name:     "linux os cue from banner fires rule7",
			in:       classifyInput{OpenPorts: []int{22}, OSCue: "linux"},
			wantType: "server", wantConf: 0.6, wantRule: "fp-server-unix-ssh",
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
		ExistingEvidence: map[string]string{"os_ttl_family": "unix-like", "l2_segment": "routed"},
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

// TestSecurityFlags asserts the insecure-service-port flags: each insecure port
// produces its "port:flag:severity" entry, the 80 http-no-tls flag is suppressed
// when 443 is also open (likely an HTTP->HTTPS redirect, not an insecure service),
// the empty case is a non-nil slice, and flags are emitted in deterministic order.
func TestSecurityFlags(t *testing.T) {
	cases := []struct {
		name  string
		ports []int
		want  []string
	}{
		{"telnet cleartext-management high", []int{23}, []string{"23:cleartext-management:high"}},
		{"ftp cleartext medium", []int{21}, []string{"21:cleartext-ftp:medium"}},
		{"http no tls info (443 closed)", []int{80}, []string{"80:http-no-tls:info"}},
		{"http flag suppressed when 443 open", []int{80, 443}, []string{}},
		{"no insecure ports", []int{22, 445}, []string{}},
		{"all three, deterministic sorted", []int{80, 23, 21}, []string{
			"21:cleartext-ftp:medium",
			"23:cleartext-management:high",
			"80:http-no-tls:info",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(classifyInput{OpenPorts: tc.ports}).SecurityFlags
			if got == nil {
				t.Fatalf("SecurityFlags is nil — a required slice must be non-nil")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SecurityFlags = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyMergeStrictValid seeds an asset with Phase-3 evidence (l2_segment +
// os_ttl_family), runs classify + mergeVerdict, and asserts the Phase-3 keys
// survive, the asset_type is refined off the "unknown" placeholder, security_flags
// and evidence stay non-nil, and the payload marshals strict-valid v5 (D-12).
func TestClassifyMergeStrictValid(t *testing.T) {
	const seg = "routed"
	a := &payload.AssetItem{
		ExternalID:     "ip:10.0.0.9",
		IPAddress:      strPtr("10.0.0.9"),
		AssetType:      "unknown",
		Services:       []payload.ServiceItem{},
		NetworkAliases: []payload.NetworkAliasItem{},
		Classification: &payload.ClassificationEvidence{
			AssetType:     "unknown",
			Confidence:    0.1,
			RuleName:      "discovery-evidence-v1",
			Evidence:      map[string]string{"l2_segment": seg, "os_ttl_family": "unix-like"},
			SecurityFlags: []string{},
		},
	}

	// 22 open (SSH) on a unix-like fingerprint with no DB -> Rule 7 server; 23
	// open (telnet) -> a cleartext-management security flag.
	in := classifyInput{
		OpenPorts:        []int{22, 23},
		ExistingEvidence: existingEvidence(a),
	}
	mergeVerdict(a, classify(in))

	if a.Classification.Evidence["l2_segment"] != seg {
		t.Errorf("l2_segment not preserved after Phase-4 classify: %v", a.Classification.Evidence)
	}
	if a.Classification.Evidence["os_ttl_family"] != "unix-like" {
		t.Errorf("os_ttl_family not preserved: %v", a.Classification.Evidence)
	}
	if a.AssetType == "unknown" || a.Classification.AssetType != a.AssetType {
		t.Errorf("asset_type not refined off the unknown placeholder: asset=%q classification=%q",
			a.AssetType, a.Classification.AssetType)
	}
	foundTelnet := false
	for _, f := range a.Classification.SecurityFlags {
		if f == "23:cleartext-management:high" {
			foundTelnet = true
		}
	}
	if !foundTelnet {
		t.Errorf("security_flags missing 23:cleartext-management:high: %v", a.Classification.SecurityFlags)
	}
	if a.Classification.Evidence == nil || a.Classification.SecurityFlags == nil {
		t.Fatalf("required containers must be non-nil")
	}

	st := scanstate.New("full", "engine/test")
	st.AddAsset(*a)
	assertStrictValid(t, marshalToMap(t, st))
}

// TestClassifyWindowsPortFallback pins the port-signature fallback: with no TTL or
// banner OS signal, an open SMB or RDP port reads as Windows. Both ports together
// reach the Windows workstation rule; either one alone sets the fingerprint and
// still reads as unknown.
func TestClassifyWindowsPortFallback(t *testing.T) {
	cases := []struct {
		name     string
		ports    []int
		wantType string
		wantConf float64
		wantRule string
	}{
		{"smb and rdp", []int{445, 3389}, "workstation", 0.8, "fp-workstation-windows"},
		{"smb only", []int{445}, "unknown", 0.0, "port-no-match"},
		{"rdp only", []int{3389}, "unknown", 0.0, "port-no-match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classify(classifyInput{OpenPorts: tc.ports})
			if v.AssetType != tc.wantType || v.Confidence != tc.wantConf || v.RuleName != tc.wantRule {
				t.Errorf("verdict = %q %v %q, want %q %v %q",
					v.AssetType, v.Confidence, v.RuleName, tc.wantType, tc.wantConf, tc.wantRule)
			}
			if v.OSHint != "windows" {
				t.Errorf("OSHint = %q, want windows", v.OSHint)
			}
			if v.Evidence["fingerprint"] != "windows" {
				t.Errorf("evidence fingerprint = %q, want windows", v.Evidence["fingerprint"])
			}
		})
	}
}

// TestClassifyWindowsPortFallbackYieldsToSignals proves the fallback never
// overrides a real OS signal, and needs SMB or RDP: a unix host running Samba
// stays unix when its TTL or banner says so. A banner naming Linux refines the
// OS hint to "linux" (never the windows fallback); a TTL-only unix-like family
// sets no hint of its own.
func TestClassifyWindowsPortFallbackYieldsToSignals(t *testing.T) {
	cases := []struct {
		name     string
		in       classifyInput
		wantFP   string
		wantHint string
	}{
		{"ttl says unix-like", classifyInput{OpenPorts: []int{445}, ExistingEvidence: map[string]string{"os_ttl_family": "unix-like"}}, "unix-like", ""},
		{"banner says linux", classifyInput{OpenPorts: []int{22, 445}, OSCue: "linux"}, "linux", "linux"},
		{"neither smb nor rdp", classifyInput{OpenPorts: []int{135, 8080}}, "", ""},
		{"no open ports", classifyInput{OpenPorts: []int{}}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := classify(tc.in)
			if v.OSHint != tc.wantHint {
				t.Errorf("OSHint = %q, want %q (the windows fallback must not fire)", v.OSHint, tc.wantHint)
			}
			if v.Evidence["fingerprint"] != tc.wantFP {
				t.Errorf("evidence fingerprint = %q, want %q", v.Evidence["fingerprint"], tc.wantFP)
			}
		})
	}
}

// TestMergeVerdictOSHint proves the fallback reaches the wire field, leaves any
// value already on the asset alone, and does not touch the OS guess: a port
// signature is not evidence for a graded guess.
func TestMergeVerdictOSHint(t *testing.T) {
	cases := []struct {
		name     string
		asset    payload.AssetItem
		wantHint string
	}{
		{"empty asset gets the hint", payload.AssetItem{}, "windows"},
		{"existing hint kept", payload.AssetItem{OSFingerprintHint: "mobile"}, "mobile"},
		{"inventory os blocks the hint", payload.AssetItem{OperatingSystem: "generic-os"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.asset
			mergeVerdict(&a, classify(classifyInput{OpenPorts: []int{445, 3389}}))
			if a.OSFingerprintHint != tc.wantHint {
				t.Errorf("OSFingerprintHint = %q, want %q", a.OSFingerprintHint, tc.wantHint)
			}
			if a.OSGuess != nil || a.OSGuessSource != nil || a.OSGuessConfidence != nil {
				t.Errorf("os_guess trio changed: %v %v %v", a.OSGuess, a.OSGuessSource, a.OSGuessConfidence)
			}
			if a.Classification.Evidence[discoveryOSTTLFamilyKey] != "" {
				t.Errorf("TTL family written by a port signature: %q", a.Classification.Evidence[discoveryOSTTLFamilyKey])
			}
		})
	}
}

// seedDiscoveredAsset builds an asset the way the discovery stage leaves a TTL-64
// host: os_fingerprint_hint and evidence os_ttl_family both "unix-like".
func seedDiscoveredAsset(ttlFamily string) *payload.AssetItem {
	ev := map[string]string{}
	if ttlFamily != "" {
		ev["os_ttl_family"] = ttlFamily
	}
	return &payload.AssetItem{
		ExternalID:        "ip:172.19.50.10",
		IPAddress:         strPtr("172.19.50.10"),
		AssetType:         "unknown",
		OSFingerprintHint: ttlFamily,
		Services:          []payload.ServiceItem{},
		NetworkAliases:    []payload.NetworkAliasItem{},
		Classification: &payload.ClassificationEvidence{
			AssetType:     "unknown",
			Confidence:    0.1,
			RuleName:      "discovery-evidence-v1",
			Evidence:      ev,
			SecurityFlags: []string{},
		},
	}
}

// classifyCase is one end-to-end classify + mergeVerdict expectation.
type classifyCase struct {
	name      string
	ttl       string // discovery os_ttl_family ("" = ICMP dropped)
	ports     []int
	osCue     string
	vendor    *string
	wantType  string
	wantConf  float64 // exact; ignored when maxConf > 0
	maxConf   float64 // upper bound instead of an exact confidence
	wantRule  string
	wantVHint string // verdict OSHint
	wantHint  string // asset os_fingerprint_hint after merge
}

func runClassifyCases(t *testing.T, cases []classifyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := seedDiscoveredAsset(tc.ttl)
			v := classify(classifyInput{
				OpenPorts:        tc.ports,
				OSCue:            tc.osCue,
				OUIVendor:        tc.vendor,
				ExistingEvidence: existingEvidence(a),
			})
			if v.AssetType != tc.wantType || v.RuleName != tc.wantRule {
				t.Errorf("verdict = %q %q, want %q %q", v.AssetType, v.RuleName, tc.wantType, tc.wantRule)
			}
			if tc.maxConf > 0 {
				if v.Confidence > tc.maxConf {
					t.Errorf("Confidence = %v, want <= %v", v.Confidence, tc.maxConf)
				}
			} else if v.Confidence != tc.wantConf {
				t.Errorf("Confidence = %v, want %v", v.Confidence, tc.wantConf)
			}
			if v.OSHint != tc.wantVHint {
				t.Errorf("verdict OSHint = %q, want %q", v.OSHint, tc.wantVHint)
			}
			mergeVerdict(a, v)
			if a.AssetType != tc.wantType {
				t.Errorf("asset_type after merge = %q, want %q", a.AssetType, tc.wantType)
			}
			if a.OSFingerprintHint != tc.wantHint {
				t.Errorf("os_fingerprint_hint after merge = %q, want %q", a.OSFingerprintHint, tc.wantHint)
			}
			if got := a.Classification.Evidence["os_ttl_family"]; got != tc.ttl {
				t.Errorf("os_ttl_family evidence = %q, want %q untouched", got, tc.ttl)
			}
		})
	}
}

// TestClassifyMoldasigRegression pins review finding N1 for the Moldasig hosts:
// headless Ubuntu sshd boxes (172.19.50.10 with 22+443, 172.19.50.15 with 22
// only, both TTL 64) are servers, not workstations, and the distro-tagged SSH
// banner refines the coarse unix-like TTL hint to linux. The DB and Samba
// exclusions and Rule 4 precedence are unchanged.
func TestClassifyMoldasigRegression(t *testing.T) {
	runClassifyCases(t, []classifyCase{
		{name: "moldasig .10 ubuntu ssh+https", ttl: "unix-like", ports: []int{22, 443}, osCue: "linux",
			wantType: "server", wantConf: 0.75, wantRule: "fp-server-unix-ssh", wantVHint: "linux", wantHint: "linux"},
		{name: "moldasig .15 ubuntu ssh only", ttl: "unix-like", ports: []int{22}, osCue: "linux",
			wantType: "server", wantConf: 0.6, wantRule: "fp-server-unix-ssh", wantVHint: "linux", wantHint: "linux"},
		{name: "ttl-only unix-like ssh", ttl: "unix-like", ports: []int{22},
			wantType: "server", wantConf: 0.6, wantRule: "fp-server-unix-ssh", wantHint: "unix-like"},
		{name: "unix-like ssh+http", ttl: "unix-like", ports: []int{22, 80},
			wantType: "server", wantConf: 0.75, wantRule: "fp-server-unix-ssh", wantHint: "unix-like"},
		{name: "unix-like ssh+db is not the unix ssh rule", ttl: "unix-like", ports: []int{22, 5432},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match", wantHint: "unix-like"},
		{name: "unix-like ssh+web+db stays rule4", ttl: "unix-like", ports: []int{22, 443, 5432},
			wantType: "server", wantConf: 0.9, wantRule: "port-server-ssh-web-db", wantHint: "unix-like"},
		{name: "unix-like samba is ambiguous", ttl: "unix-like", ports: []int{22, 445},
			wantType: "unknown", wantConf: 0.0, wantRule: "port-no-match", wantHint: "unix-like"},
		{name: "windows ttl smb+rdp unchanged", ttl: "windows", ports: []int{445, 3389},
			wantType: "workstation", wantConf: 0.8, wantRule: "fp-workstation-windows", wantHint: "windows"},
	})
	// The string "fp-workstation-linux" is retired: no input may yield it.
	for _, ports := range [][]int{{22}, {22, 80}, {22, 443}} {
		v := classify(classifyInput{OpenPorts: ports, ExistingEvidence: map[string]string{"os_ttl_family": "unix-like"}})
		if v.RuleName == "fp-workstation-linux" || v.AssetType == "workstation" {
			t.Errorf("ports %v: verdict %q %q, want no unix workstation rule", ports, v.AssetType, v.RuleName)
		}
	}
}

// TestClassifyApple pins the Apple rule (review finding N1): a Mac Mini, iPhone or
// iPad answers TTL 64 like Linux, so an Apple OUI or the iOS lockdown port must
// keep the host off "linux" and off "server". AirPlay plus Kerberos/SMB is the
// macOS desktop profile; 62078 is iOS; an Apple OUI alone stays unknown.
func TestClassifyApple(t *testing.T) {
	apple := strPtr("Apple, Inc.")
	runClassifyCases(t, []classifyCase{
		{name: "mac mini full port set", ttl: "unix-like", ports: []int{88, 445, 5000, 7000}, vendor: apple,
			wantType: "workstation", maxConf: 0.6, wantRule: "fp-apple-macos", wantVHint: "macos", wantHint: "macos"},
		{name: "mac default scan set (no 5000)", ttl: "unix-like", ports: []int{88, 445, 7000}, vendor: apple,
			wantType: "workstation", maxConf: 0.6, wantRule: "fp-apple-macos", wantVHint: "macos", wantHint: "macos"},
		{name: "mac with remote login is never a server", ttl: "unix-like", ports: []int{22, 88, 445, 7000}, vendor: apple,
			wantType: "workstation", maxConf: 0.6, wantRule: "fp-apple-macos", wantVHint: "macos", wantHint: "macos"},
		{name: "ios lockdown port", ttl: "unix-like", ports: []int{62078}, vendor: apple,
			wantType: "unknown", maxConf: 0.5, wantRule: "fp-apple-ios", wantVHint: "ios", wantHint: "ios"},
		{name: "apple oui with ssh only", ttl: "unix-like", ports: []int{22}, vendor: apple,
			wantType: "unknown", maxConf: 0.5, wantRule: "fp-apple-device", wantVHint: "apple", wantHint: "apple"},
		{name: "apple oui with airplay only", ttl: "unix-like", ports: []int{7000}, vendor: apple,
			wantType: "unknown", maxConf: 0.5, wantRule: "fp-apple-device", wantVHint: "apple", wantHint: "apple"},
		{name: "apple icmp dropped: macos beats windows fallback", ttl: "", ports: []int{88, 445, 7000}, vendor: apple,
			wantType: "workstation", maxConf: 0.6, wantRule: "fp-apple-macos", wantVHint: "macos", wantHint: "macos"},
	})

	// The Apple hint replaces the SMB windows-fallback fingerprint in evidence too.
	v := classify(classifyInput{OpenPorts: []int{88, 445, 7000}, OUIVendor: apple})
	if v.Evidence["fingerprint"] != "macos" {
		t.Errorf("evidence fingerprint = %q, want macos", v.Evidence["fingerprint"])
	}
}
