// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// Deterministic device classification for the port stage (PORT-05, D-08/D-09/
// D-10/D-12).
//
// classify() turns the open-port signature, banner-derived hints, the OUI vendor,
// and the OS fingerprint (the Phase-3 TTL family plus a banner OS cue) into a
// verdict, via a first-match-wins precedence engine of eight rules. It re-probes
// nothing: every signal is already on the classifyInput the orchestrator
// assembled. The engine is a pure function — identical input yields a
// byte-identical verdict — so the pipeline is reproducible.
//
// Every verdict is source- and confidence-labeled on the evidence map (D-08): a
// TTL family or a banner string is attacker-spoofable, so no Phase-4 value is
// emitted as authoritative. A later, higher-fidelity stage (real fingerprinting)
// runs afterwards and overrides a coarse Phase-4 verdict when its confidence is
// higher. The classifier emits EVIDENCE ONLY; it never decides compliance state.
//
// mergeVerdict applies the verdict with the merge-never-replace discipline the
// discovery classifier established: it writes INTO the existing classification
// evidence map rather than replacing it, so a routed host keeps its l2_segment
// key and discovery's os_ttl_family / mdns / netbios evidence survives (D-12).

const (
	// Per-rule names. Each labels a Phase-4 port-stage verdict so an auditor (and
	// a later stage) can tell which signal produced the asset_type.
	ruleBannerHTTPPrefix   = "banner-http-"
	ruleNetworkVendorSNMP  = "port-network-vendor-snmp"
	ruleIoTVendor          = "port-iot-vendor"
	ruleServerSSHWebDB     = "port-server-ssh-web-db"
	ruleServerWindowsFP    = "fp-server-windows"
	ruleWorkstationWindows = "fp-workstation-windows"
	ruleWorkstationLinux   = "fp-workstation-linux"
	rulePrinterPorts       = "port-printer-ports"
	ruleNoMatch            = "port-no-match"

	// asset_type enum — these six values match the cloud ingest enum exactly; a
	// value outside this set is silently dropped at the boundary.
	assetTypeServer      = "server"
	assetTypeWorkstation = "workstation"
	assetTypePrinter     = "printer"
	assetTypeIoT         = "iot"
	assetTypeNetwork     = "network"
	assetTypeUnknown     = "unknown"

	// Well-known ports the rules key off.
	portFTP       = 21
	portTelnet    = 23
	portSSH       = 22
	portHTTP      = 80
	portHTTPS     = 443
	portSNMP      = 161
	portSMB       = 445
	portRDP       = 3389
	portIPP       = 631
	portJetDirect = 9100

	// classifySource labels every Phase-4 verdict so a later higher-fidelity stage
	// knows the value is overridable (D-08).
	classifySource = "port-banner-v1"

	// Evidence keys written by the port classifier. These are distinct from the
	// discovery-stage keys (mac_vendor/os_ttl_family/mdns/netbios/l2_segment) so a
	// merge never clobbers the Phase-3 evidence.
	evidenceKeyPortSignature   = "port_signature"
	evidenceKeyOUIVendor       = "oui_vendor"
	evidenceKeyFingerprint     = "fingerprint"
	evidenceKeyProductHint     = "banner_product_hint"
	evidenceKeyOSCue           = "banner_os_cue"
	evidenceKeyAssetTypeSource = "asset_type_source"
	evidenceKeyAssetTypeConf   = "asset_type_confidence"
)

// dbPorts are the database service ports: a host offering one alongside SSH and a
// web port reads as a server (Rule 4), while an SSH-only Linux host with a DB is
// deliberately NOT a workstation (Rule 7 excludes it).
var dbPorts = map[int]bool{3306: true, 5432: true, 1433: true, 27017: true}

// printerPorts are the two well-known print-service ports: IPP (631) and HP
// JetDirect (9100). Either open is a strong printer signal (Rule 1).
var printerPorts = map[int]bool{portIPP: true, portJetDirect: true}

// networkVendors are lowercased OUI substrings for networking-gear makers. An OUI
// whose organisation contains one of these, paired with an SNMP or SSH port, reads
// as network infrastructure (Rule 2). Substrings (not exact matches) so a vendor's
// full registered name — e.g. "Cisco Systems, Inc" — still matches "cisco".
var networkVendors = []string{
	"cisco", "juniper", "mikrotik", "ubiquiti", "aruba",
	"hewlett packard enterprise", "fortinet", "extreme networks",
	"tp-link", "tp link", "tenda", "huawei", "zte", "fiberhome",
	"netgear", "asus", "d-link", " technicolor", "routerboard", "avm",
}

// iotVendors are lowercased OUI substrings for consumer-IoT / embedded-module
// makers. A match on a host with a small open-port footprint reads as IoT (Rule 3).
var iotVendors = []string{
	"philips lighting", "signify", "hue", "nest", "sonos", "ring", "ecobee",
	"amazon technologies", "google", "tuya", "lg innotek", "ampak", "espressif",
	"realtek", "mediatek", "raspberry pi", "silicon labs", "nordic semiconductor",
	"silicondust", "shenzhen",
}

// broadModuleVendors are the three OUI substrings that belong to high-volume chip/
// module makers whose silicon ends up in countless unrelated devices. A match on
// its own is too weak to call IoT — Rule 3 requires at least one open port before
// trusting a broad-module vendor, so a dark host with such an OUI falls through.
var broadModuleVendors = []string{"realtek", "mediatek", "shenzhen"}

// insecureFlag is the flag name + severity raised for an open insecure-service
// port.
type insecureFlag struct {
	flag     string
	severity string
}

// insecureServicePorts maps an open port that exposes a plaintext/insecure service
// to the security flag it raises. Telnet (23) is cleartext management and the most
// serious; FTP (21) is cleartext file transfer; plain HTTP (80) is only
// informational — and is suppressed entirely when 443 is also open (see
// securityFlags), since that pairing is almost always an HTTP->HTTPS redirect
// rather than an exposed insecure service.
var insecureServicePorts = map[int]insecureFlag{
	portTelnet: {"cleartext-management", "high"},
	portFTP:    {"cleartext-ftp", "medium"},
	portHTTP:   {"http-no-tls", "info"},
}

// securityFlags derives the "port:flag:severity" entries for every open insecure
// service port, in deterministic ascending-port order. The HTTP (80) flag is
// suppressed when HTTPS (443) is also open — that combination reads as a redirect
// to TLS, not a bare insecure service. The result is always a non-nil slice (empty
// when nothing insecure is open) so the required container never marshals to null.
func securityFlags(openPorts []int) []string {
	flags := []string{}
	has443 := containsPort(openPorts, portHTTPS)

	ports := make([]int, 0, len(insecureServicePorts))
	for p := range insecureServicePorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	for _, p := range ports {
		if !containsPort(openPorts, p) {
			continue
		}
		if p == portHTTP && has443 {
			continue // HTTP->HTTPS redirect, not an exposed insecure service
		}
		f := insecureServicePorts[p]
		flags = append(flags, fmt.Sprintf("%d:%s:%s", p, f.flag, f.severity))
	}
	return flags
}

// classifyInput bundles everything the classifier reads: the open ports, the
// per-port banner text, the single aggregated product/OS hint, the OUI vendor (nil
// when unknown), and the evidence discovery already recorded (so the classifier
// can read os_ttl_family/mdns/netbios without re-probing).
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

// hintVerdict is a Rule-0 banner-driven mapping: a coarse product hint parsed from
// a banner maps straight to a high-confidence asset type. Banner evidence is the
// strongest Phase-4 signal, so Rule 0 runs first and outranks the port/vendor/
// fingerprint rules.
type hintVerdict struct {
	assetType  string
	confidence float64
}

// productHintVerdicts maps a banner product hint to its Rule-0 verdict. The rule
// name is derived as "banner-http-<hint>" so the auditor sees which cue fired.
var productHintVerdicts = map[string]hintVerdict{
	"router":  {assetTypeNetwork, 0.95},
	"camera":  {assetTypeIoT, 0.9},
	"echo":    {assetTypeIoT, 0.9},
	"printer": {assetTypePrinter, 0.95},
	"nas":     {assetTypeServer, 0.85},
	"openwrt": {assetTypeNetwork, 0.85},
}

// classify produces a verdict from the open-port signature, banner hints, OUI
// vendor, and OS fingerprint via first-match-wins precedence. Every verdict
// records the sorted port signature plus the D-08 source/confidence provenance so
// the value is honestly graded and overridable.
func classify(in classifyInput) verdict {
	v := verdict{
		Evidence:      map[string]string{},
		SecurityFlags: securityFlags(in.OpenPorts),
	}

	sig := portSignature(in.OpenPorts)
	fp := osFingerprint(in)
	vendor := ""
	if in.OUIVendor != nil {
		vendor = strings.ToLower(*in.OUIVendor)
	}

	v.AssetType, v.Confidence, v.RuleName = applyRules(in, fp, vendor)

	v.Evidence[evidenceKeyPortSignature] = sig
	if vendor != "" {
		v.Evidence[evidenceKeyOUIVendor] = vendor
	}
	if fp != "" {
		v.Evidence[evidenceKeyFingerprint] = fp
	}
	if in.ProductHint != "" {
		v.Evidence[evidenceKeyProductHint] = in.ProductHint
	}
	if in.OSCue != "" {
		v.Evidence[evidenceKeyOSCue] = in.OSCue
	}
	v.Evidence[evidenceKeyAssetTypeSource] = classifySource
	v.Evidence[evidenceKeyAssetTypeConf] = strconv.FormatFloat(v.Confidence, 'f', -1, 64)
	return v
}

// applyRules runs the eight rules in precedence order and returns the first match
// (asset type, confidence, rule name), or the unknown fall-through.
func applyRules(in classifyInput, fp, vendor string) (assetType string, confidence float64, ruleName string) {
	// Rule 0 — banner-driven product hint (highest precedence): a banner we parsed
	// into a product hint is the strongest Phase-4 signal, so it beats the port and
	// vendor rules below.
	if hv, ok := productHintVerdicts[in.ProductHint]; ok {
		return hv.assetType, hv.confidence, ruleBannerHTTPPrefix + in.ProductHint
	}

	// Rule 1 — printer ports: IPP or JetDirect open is a strong, direct signal.
	if hasAnyPort(in.OpenPorts, printerPorts) {
		return assetTypePrinter, 0.9, rulePrinterPorts
	}

	// Rule 2 — network vendor + management port: a networking-gear OUI paired with
	// SNMP or SSH reads as infrastructure.
	if (containsPort(in.OpenPorts, portSNMP) || containsPort(in.OpenPorts, portSSH)) &&
		matchesVendor(vendor, networkVendors) {
		return assetTypeNetwork, 0.85, ruleNetworkVendorSNMP
	}

	// Rule 3 — IoT vendor with a small footprint: an IoT/embedded OUI on a host
	// with <=4 open ports reads as IoT. A broad-module vendor (chip maker whose
	// silicon is everywhere) is too weak on its own — require >=1 open port.
	if matchesVendor(vendor, iotVendors) && len(in.OpenPorts) <= 4 {
		if !matchesVendor(vendor, broadModuleVendors) || len(in.OpenPorts) >= 1 {
			return assetTypeIoT, 0.8, ruleIoTVendor
		}
	}

	// Rule 4 — server: SSH plus a web port plus a database port is a server stack.
	if containsPort(in.OpenPorts, portSSH) &&
		(containsPort(in.OpenPorts, portHTTP) || containsPort(in.OpenPorts, portHTTPS)) &&
		hasAnyPort(in.OpenPorts, dbPorts) {
		return assetTypeServer, 0.9, ruleServerSSHWebDB
	}

	// Rule 5 — Windows server fingerprint: largely dormant in Phase 4 (the coarse
	// TTL/banner hint rarely carries "server"); it wakes up when a later stage
	// supplies a real "windows server" fingerprint.
	if strings.Contains(fp, "windows") && strings.Contains(fp, "server") {
		return assetTypeServer, 0.85, ruleServerWindowsFP
	}

	// Rule 6 — Windows workstation: a Windows fingerprint with SMB and RDP open.
	if strings.Contains(fp, "windows") &&
		containsPort(in.OpenPorts, portSMB) && containsPort(in.OpenPorts, portRDP) {
		return assetTypeWorkstation, 0.8, ruleWorkstationWindows
	}

	// Rule 7 — Linux workstation: a Linux/Unix fingerprint with SSH open and no DB
	// port (a DB would make it a server, not a workstation). Lowest confidence
	// because SSH-on-Linux is the weakest of the fingerprint signals.
	if (strings.Contains(fp, "linux") || strings.Contains(fp, "unix")) &&
		containsPort(in.OpenPorts, portSSH) && !hasAnyPort(in.OpenPorts, dbPorts) {
		return assetTypeWorkstation, 0.6, ruleWorkstationLinux
	}

	// Fall-through: no rule matched.
	return assetTypeUnknown, 0.0, ruleNoMatch
}

// osFingerprint builds the lowercased OS hint the fingerprint rules read, by
// combining the Phase-3 TTL family (os_ttl_family, from ExistingEvidence) with the
// banner-derived OS cue (D-10). Both are low-confidence, attacker-spoofable
// signals — the grading on the verdict keeps them honest.
func osFingerprint(in classifyInput) string {
	parts := make([]string, 0, 2)
	if fam := in.ExistingEvidence[discoveryOSTTLFamilyKey]; fam != "" {
		parts = append(parts, strings.ToLower(fam))
	}
	if in.OSCue != "" {
		parts = append(parts, strings.ToLower(in.OSCue))
	}
	return strings.Join(parts, " ")
}

// discoveryOSTTLFamilyKey is the evidence key the discovery stage writes the
// coarse TTL-derived OS family under; the classifier reads it to seed its OS
// fingerprint without re-probing.
const discoveryOSTTLFamilyKey = "os_ttl_family"

// matchesVendor reports whether the lowercased OUI vendor contains any of the
// lowercased substrings in list.
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

// hasAnyPort reports whether any port in ports is present in set.
func hasAnyPort(ports []int, set map[int]bool) bool {
	for _, p := range ports {
		if set[p] {
			return true
		}
	}
	return false
}

// portSignature renders the open-port list as a sorted, deduped comma-joined
// string, so equal port sets collide to the same signature regardless of the order
// (or duplicates) in which they were discovered (PORT-05 adjacency edge).
func portSignature(ports []int) string {
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	parts := make([]string, 0, len(sorted))
	var last int
	for i, p := range sorted {
		if i > 0 && p == last {
			continue
		}
		parts = append(parts, strconv.Itoa(p))
		last = p
	}
	return strings.Join(parts, ",")
}

// mergeVerdict merges the verdict into the asset's classification WITHOUT
// replacing it: it nil-guards the classification pointer, initialises the evidence
// map and security-flags slice when absent, writes each verdict evidence entry
// INTO the existing map (preserving discovery's l2_segment/os_ttl_family/mdns/
// netbios keys), appends the verdict's security flags, and sets the asset type /
// confidence / rule name on both the classification and the asset.
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
