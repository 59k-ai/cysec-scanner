// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/netutil"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
	"github.com/59k-ai/cysec-scanner/payload"
)

// TestMain defaults the hostname-resolver seams to no-ops so Run-based tests do
// no real DNS/mDNS/NetBIOS network I/O, and empties the own-interface MAC seam
// so no test reads the developer machine's real interfaces (a fixture subnet can
// be the developer's own LAN). Tests that need either override the seams
// explicitly and restore them.
func TestMain(m *testing.M) {
	resolveRDNS = func(context.Context, string, time.Duration) string { return "" }
	resolveMDNS = func(context.Context, string, time.Duration) string { return "" }
	resolveNetBIOS = func(context.Context, string, time.Duration) netutil.NetBIOSStatus { return netutil.NetBIOSStatus{} }
	localInterfaceMACs = func() map[string]string { return map[string]string{} }
	os.Exit(m.Run())
}

// marshalToMap round-trips the accumulator payload through JSON into a generic
// map, so a required slice emitted as JSON null (nil) is distinguishable from an
// empty literal [] (a non-nil []any) — the strict-v6 invariant.
func marshalToMap(t *testing.T, st *scanstate.ScanState) map[string]any {
	t.Helper()
	pl := st.Payload()
	pl.Normalize()
	data, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

// assertStrictValid asserts schema_version == payload.SchemaVersion and that assets is a JSON list
// (never null).
func assertStrictValid(t *testing.T, m map[string]any) []any {
	t.Helper()
	if sv, _ := m["schema_version"].(float64); sv != float64(payload.SchemaVersion) {
		t.Fatalf("schema_version = %v, want %d", m["schema_version"], payload.SchemaVersion)
	}
	assets, ok := m["assets"].([]any)
	if !ok {
		t.Fatalf("assets is not a JSON list (got %T) — a null required slice is strict-invalid", m["assets"])
	}
	return assets
}

// TestTracerEndToEnd is the Phase-3 tracer: an injected-live host becomes exactly
// one strict-valid v6 asset in the accumulator, and the zero-live case still
// emits a strict-valid payload with assets == [].
func TestTracerEndToEnd(t *testing.T) {
	orig := sweepHosts
	defer func() { sweepHosts = orig }()

	// One live host injected (no real packets).
	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return []netutil.SweepResult{{IP: "127.0.0.1", TTL: 64}}
	}
	st := scanstate.New("full", "engine/test")
	if err := Run(context.Background(), st, capabilities.Capabilities{}, []string{"127.0.0.1/32"}); err != nil {
		t.Fatalf("Run (live): %v", err)
	}
	m := marshalToMap(t, st)
	assets := assertStrictValid(t, m)
	if len(assets) != 1 {
		t.Fatalf("live case produced %d assets, want 1", len(assets))
	}
	a := assets[0].(map[string]any)
	if a["external_id"] != "ip:127.0.0.1" {
		t.Errorf("external_id = %v, want ip:127.0.0.1", a["external_id"])
	}
	if a["ip_address"] != "127.0.0.1" {
		t.Errorf("ip_address = %v, want 127.0.0.1", a["ip_address"])
	}
	if _, ok := a["services"].([]any); !ok {
		t.Errorf("asset services is not a JSON list (got %T) — must be [] not null", a["services"])
	}
	if _, ok := a["network_aliases"].([]any); !ok {
		t.Errorf("asset network_aliases is not a JSON list (got %T) — must be [] not null", a["network_aliases"])
	}

	// No live host -> still a strict-valid payload with assets == [].
	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return nil
	}
	st2 := scanstate.New("full", "engine/test")
	if err := Run(context.Background(), st2, capabilities.Capabilities{}, []string{"127.0.0.1/32"}); err != nil {
		t.Fatalf("Run (zero): %v", err)
	}
	assets2 := assertStrictValid(t, marshalToMap(t, st2))
	if len(assets2) != 0 {
		t.Fatalf("zero-live case produced %d assets, want 0", len(assets2))
	}
}

// runWithL2 runs discovery with injected sweep/ARP/local-network seams and the
// ARP capability on, returning the resulting assets decoded from JSON and keyed
// by external_id. A real OUI MAC (28:6f:b9… = MA-L Nokia Shanghai Bell) lets the
// vendor lookup resolve against the embedded registry.
func runWithL2(t *testing.T, live []netutil.SweepResult, arp map[string]string, local []string) map[string]map[string]any {
	t.Helper()
	origSweep, origARP, origLocal := sweepHosts, arpTable, localNetworks
	defer func() { sweepHosts, arpTable, localNetworks = origSweep, origARP, origLocal }()

	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return live
	}
	arpTable = func() map[string]string { return arp }
	localNetworks = func() []string { return local }

	st := scanstate.New("full", "engine/test")
	caps := capabilities.Capabilities{ARPCache: true}
	if err := Run(context.Background(), st, caps, []string{"10.0.0.0/24"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assets := assertStrictValid(t, marshalToMap(t, st))
	out := map[string]map[string]any{}
	for _, a := range assets {
		am := a.(map[string]any)
		out[am["external_id"].(string)] = am
	}
	return out
}

func keysOf(m map[string]map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// TestEnrichL2States proves the three distinct L2 states, now distinguished by
// the l2_segment evidence key and the MAC states rather than by presence/absence
// of classification evidence (DISC-05: EVERY asset carries classification
// evidence). A local host carries a real MAC + OUI vendor with a stabilized
// mac:<mac> identity, classification evidence WITHOUT an l2_segment key, and a
// mac_vendor evidence entry; a routed host carries a null MAC, the sentinel
// vendor, and an l2_segment=routed evidence key; a not-observed host (within a
// local segment but absent from the ARP cache) stays MAC-null with classification
// evidence that has NO l2_segment key and NO mac_vendor entry.
func TestEnrichL2States(t *testing.T) {
	live := []netutil.SweepResult{
		{IP: "10.0.0.5", TTL: 64},    // local: has an ARP entry
		{IP: "203.0.113.9", TTL: 54}, // routed: no ARP entry, outside local CIDR
		{IP: "10.0.0.7", TTL: 64},    // not observed: in local CIDR, no ARP entry
	}
	arp := map[string]string{"10.0.0.5": "28:6f:b9:00:00:01"}
	assets := runWithL2(t, live, arp, []string{"10.0.0.0/24"})

	// Local host: re-keyed to mac:<mac>, real MAC + vendor, classification
	// evidence carrying a mac_vendor entry but NO l2_segment key.
	local, ok := assets["mac:28:6f:b9:00:00:01"]
	if !ok {
		t.Fatalf("local host not re-keyed to mac:<mac>; keys=%v", keysOf(assets))
	}
	if local["mac_address"] != "28:6f:b9:00:00:01" {
		t.Errorf("local mac_address = %v, want 28:6f:b9:00:00:01", local["mac_address"])
	}
	if v, _ := local["mac_vendor"].(string); v == "" || v == macVendorNotOnLocalSegment {
		t.Errorf("local mac_vendor = %q, want a real OUI vendor", v)
	}
	lce, ok := local["classification_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("local classification_evidence missing (got %T) — every asset carries evidence now", local["classification_evidence"])
	}
	if lce["asset_type"] != assetTypeUnknown {
		t.Errorf("local asset_type = %v, want %q", lce["asset_type"], assetTypeUnknown)
	}
	lev, _ := lce["evidence"].(map[string]any)
	if _, has := lev[evidenceKeyL2Segment]; has {
		t.Errorf("local host must NOT carry an l2_segment key, got %v", lev[evidenceKeyL2Segment])
	}
	if lev[evidenceKeyMACVendor] == nil || lev[evidenceKeyMACVendor] == "" {
		t.Errorf("local host must carry a mac_vendor evidence entry, got %v", lev[evidenceKeyMACVendor])
	}

	// Routed host: null MAC, sentinel vendor, l2_segment=routed evidence.
	routed, ok := assets["ip:203.0.113.9"]
	if !ok {
		t.Fatalf("routed host missing; keys=%v", keysOf(assets))
	}
	if routed["mac_address"] != nil {
		t.Errorf("routed mac_address = %v, want null", routed["mac_address"])
	}
	if routed["mac_vendor"] != macVendorNotOnLocalSegment {
		t.Errorf("routed mac_vendor = %v, want sentinel %q", routed["mac_vendor"], macVendorNotOnLocalSegment)
	}
	ce, ok := routed["classification_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("routed classification_evidence missing (got %T)", routed["classification_evidence"])
	}
	ev, _ := ce["evidence"].(map[string]any)
	if ev[evidenceKeyL2Segment] != evidenceValueRouted {
		t.Errorf("routed evidence[%q] = %v, want %q", evidenceKeyL2Segment, ev[evidenceKeyL2Segment], evidenceValueRouted)
	}

	// Not-observed host: MAC-null (never L2-assigned), with classification
	// evidence that has NO l2_segment key and NO mac_vendor entry — the honest
	// "not observed" L2 state, distinct from routed.
	notObs, ok := assets["ip:10.0.0.7"]
	if !ok {
		t.Fatalf("not-observed host missing; keys=%v", keysOf(assets))
	}
	if notObs["mac_address"] != nil || notObs["mac_vendor"] != nil {
		t.Errorf("not-observed host must have null MAC + null vendor, got mac=%v vendor=%v", notObs["mac_address"], notObs["mac_vendor"])
	}
	nce, ok := notObs["classification_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("not-observed classification_evidence missing (got %T)", notObs["classification_evidence"])
	}
	nev, _ := nce["evidence"].(map[string]any)
	if _, has := nev[evidenceKeyL2Segment]; has {
		t.Errorf("not-observed host must NOT carry an l2_segment key, got %v", nev[evidenceKeyL2Segment])
	}
	if _, has := nev[evidenceKeyMACVendor]; has {
		t.Errorf("not-observed host must NOT carry a mac_vendor entry, got %v", nev[evidenceKeyMACVendor])
	}
}

// TestEnrichL2HarvestsARPOnlyHost proves a host that answered ARP but stayed
// ICMP-silent (the Windows Public-profile case) is harvested into the set and
// keyed by its stable mac:<mac> identity.
func TestEnrichL2HarvestsARPOnlyHost(t *testing.T) {
	live := []netutil.SweepResult{{IP: "10.0.0.5", TTL: 64}}
	arp := map[string]string{
		"10.0.0.5":  "28:6f:b9:00:00:01",
		"10.0.0.50": "28:6f:b9:00:00:02", // ARP-only, never answered ICMP
	}
	assets := runWithL2(t, live, arp, []string{"10.0.0.0/24"})
	if _, ok := assets["mac:28:6f:b9:00:00:02"]; !ok {
		t.Fatalf("ARP-only host not harvested; keys=%v", keysOf(assets))
	}
}

// TestEnrichL2DropsOutOfScopeARPHost is the phase-03 verifier BLOCKER regression:
// an ARP-cache neighbour OUTSIDE the resolved scan scope must never be harvested
// into an asset. The scenario mirrors `--cidr 192.0.2.0/30` (TEST-NET-1, no live
// hosts) run on a box whose kernel ARP cache holds a 192.168.1.x neighbour from a
// different interface/segment: the sweep returns zero in-scope hosts, yet the
// stale ARP entry must NOT leak into the payload (Phase 4 would otherwise
// port-scan an out-of-scope host). The payload for the empty in-scope scope must
// still be strict-valid v6 with assets == [].
func TestEnrichL2DropsOutOfScopeARPHost(t *testing.T) {
	origSweep, origARP, origLocal := sweepHosts, arpTable, localNetworks
	defer func() { sweepHosts, arpTable, localNetworks = origSweep, origARP, origLocal }()

	// Zero live hosts answer the sweep within the requested scope.
	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return nil
	}
	// The kernel ARP cache holds only an out-of-scope neighbour, as it would after
	// the host talked to a docker/VPN/other-segment address.
	arpTable = func() map[string]string {
		return map[string]string{"192.168.1.50": "28:6f:b9:00:00:02"}
	}
	// localNetworks reports the real local segment (192.168.1.0/24), distinct from
	// the explicit, narrow scan scope below — proving the harvest is bounded by the
	// resolved SCOPE, not by localNetworks.
	localNetworks = func() []string { return []string{"192.168.1.0/24"} }

	st := scanstate.New("full", "engine/test")
	caps := capabilities.Capabilities{ARPCache: true}
	if err := Run(context.Background(), st, caps, []string{"192.0.2.0/30"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assets := assertStrictValid(t, marshalToMap(t, st))
	if len(assets) != 0 {
		t.Fatalf("out-of-scope ARP neighbour leaked into %d assets, want 0 (BLOCKER: ARP harvest must be scope-bounded)", len(assets))
	}
}

// TestEnrichL2ClaimedMACGuard proves a MAC already claimed by one asset does not
// collapse a second host's identity: with two IPs behind one MAC (proxy/shared
// MAC) the lowest IP claims mac:<mac> and the other keeps its ip:<ip> identity,
// so two distinct assets remain.
func TestEnrichL2ClaimedMACGuard(t *testing.T) {
	shared := "28:6f:b9:00:00:01"
	live := []netutil.SweepResult{
		{IP: "10.0.0.5", TTL: 64},
		{IP: "10.0.0.6", TTL: 64},
	}
	arp := map[string]string{"10.0.0.5": shared, "10.0.0.6": shared}
	assets := runWithL2(t, live, arp, []string{"10.0.0.0/24"})
	if _, ok := assets["mac:"+shared]; !ok {
		t.Fatalf("shared MAC must be claimed by one asset; keys=%v", keysOf(assets))
	}
	if _, ok := assets["ip:10.0.0.6"]; !ok {
		t.Fatalf("second host behind a claimed MAC must keep ip:<ip>; keys=%v", keysOf(assets))
	}
	if len(assets) != 2 {
		t.Fatalf("want 2 distinct assets, got %d: %v", len(assets), keysOf(assets))
	}
}

// TestEnrichHostnames proves the DISC-04 producer contract: hostname precedence
// (rDNS -> mDNS -> NetBIOS), the per-resolver hit flags recorded for EVERY
// resolver that answered (including one that answered but lost precedence), and
// the empty-on-total-miss path with all flags false.
func TestEnrichHostnames(t *testing.T) {
	origR, origM, origN := resolveRDNS, resolveMDNS, resolveNetBIOS
	defer func() { resolveRDNS, resolveMDNS, resolveNetBIOS = origR, origM, origN }()

	resolveRDNS = func(_ context.Context, ip string, _ time.Duration) string {
		if ip == "10.0.0.5" {
			return "host5.example.com"
		}
		return ""
	}
	resolveMDNS = func(_ context.Context, ip string, _ time.Duration) string {
		switch ip {
		case "10.0.0.5":
			return "host5.local" // answers, but loses precedence to rDNS
		case "10.0.0.6":
			return "host6.local" // wins (no rDNS)
		}
		return ""
	}
	resolveNetBIOS = func(_ context.Context, ip string, _ time.Duration) netutil.NetBIOSStatus {
		if ip == "10.0.0.7" {
			return netutil.NetBIOSStatus{Name: "WORKSTATION7"} // wins (no rDNS, no mDNS)
		}
		return netutil.NetBIOSStatus{}
	}

	entries := map[string]hostEntry{
		"ip:10.0.0.5": {ip: "10.0.0.5"},
		"ip:10.0.0.6": {ip: "10.0.0.6"},
		"ip:10.0.0.7": {ip: "10.0.0.7"},
		"ip:10.0.0.8": {ip: "10.0.0.8"}, // total miss
	}
	enrichHostnames(context.Background(), entries)

	// host5: rDNS wins the name, but mDNS also answered -> both flags set.
	h5 := entries["ip:10.0.0.5"]
	if h5.hostname != "host5.example.com" {
		t.Errorf("host5 hostname = %q, want host5.example.com (rDNS precedence)", h5.hostname)
	}
	if !h5.rdnsHit || !h5.mdnsHit {
		t.Errorf("host5 flags: rdns=%v mdns=%v, want both true (mDNS answered but lost precedence)", h5.rdnsHit, h5.mdnsHit)
	}
	if h5.netbiosHit {
		t.Errorf("host5 netbiosHit = true, want false (NetBIOS did not answer)")
	}

	// host6: mDNS wins.
	h6 := entries["ip:10.0.0.6"]
	if h6.hostname != "host6.local" {
		t.Errorf("host6 hostname = %q, want host6.local", h6.hostname)
	}
	if h6.rdnsHit || !h6.mdnsHit || h6.netbiosHit {
		t.Errorf("host6 flags: rdns=%v mdns=%v netbios=%v, want false/true/false", h6.rdnsHit, h6.mdnsHit, h6.netbiosHit)
	}

	// host7: NetBIOS wins.
	h7 := entries["ip:10.0.0.7"]
	if h7.hostname != "WORKSTATION7" {
		t.Errorf("host7 hostname = %q, want WORKSTATION7", h7.hostname)
	}
	if h7.rdnsHit || h7.mdnsHit || !h7.netbiosHit {
		t.Errorf("host7 flags: rdns=%v mdns=%v netbios=%v, want false/false/true", h7.rdnsHit, h7.mdnsHit, h7.netbiosHit)
	}

	// host8: total miss -> empty hostname, all flags false.
	h8 := entries["ip:10.0.0.8"]
	if h8.hostname != "" {
		t.Errorf("host8 hostname = %q, want \"\" (total miss)", h8.hostname)
	}
	if h8.rdnsHit || h8.mdnsHit || h8.netbiosHit {
		t.Errorf("host8 flags must all be false on a total miss, got rdns=%v mdns=%v netbios=%v", h8.rdnsHit, h8.mdnsHit, h8.netbiosHit)
	}
}

// TestHostnameOnAsset proves a resolved hostname reaches AssetItem.Hostname/FQDN
// and that the payload stays strict-valid, and that a total miss leaves the
// hostname empty without breaking strict validity.
func TestHostnameOnAsset(t *testing.T) {
	origSweep, origR := sweepHosts, resolveRDNS
	defer func() { sweepHosts, resolveRDNS = origSweep, origR }()

	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return []netutil.SweepResult{{IP: "10.1.2.3", TTL: 64}}
	}
	resolveRDNS = func(_ context.Context, ip string, _ time.Duration) string {
		if ip == "10.1.2.3" {
			return "named-host.example.com"
		}
		return ""
	}

	st := scanstate.New("full", "engine/test")
	if err := Run(context.Background(), st, capabilities.Capabilities{}, []string{"10.1.2.3/32"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assets := assertStrictValid(t, marshalToMap(t, st))
	if len(assets) != 1 {
		t.Fatalf("produced %d assets, want 1", len(assets))
	}
	a := assets[0].(map[string]any)
	if a["hostname"] != "named-host.example.com" {
		t.Errorf("asset hostname = %v, want named-host.example.com", a["hostname"])
	}
	if a["fqdn"] != "named-host.example.com" {
		t.Errorf("asset fqdn = %v, want named-host.example.com", a["fqdn"])
	}
}

// TestDiscoveryPayloadStrictValid is the phase-closing DISC-05 end-to-end gate:
// it drives discovery.Run with an injected sweep (one local host with a
// MAC/vendor + TTL, one routed host outside the local segment) into a scanstate
// accumulator, marshals the accumulated payload the way main.go does (after
// Normalize), and asserts the JSON is strict-valid populated with assets:
// schema_version == payload.SchemaVersion; assets a non-empty list; for EVERY asset services /
// network_aliases / classification_evidence.evidence / security_flags are
// non-null and asset_type is "unknown"; the local host has a real
// mac_address + mac_vendor; the routed host has a null mac_address, the sentinel
// mac_vendor, and evidence["l2_segment"]=="routed". Strict validity is proven
// entirely in-tree (the payload's Normalize guards + this structural check),
// with no external validation tooling.
func TestDiscoveryPayloadStrictValid(t *testing.T) {
	origSweep, origARP, origLocal := sweepHosts, arpTable, localNetworks
	defer func() { sweepHosts, arpTable, localNetworks = origSweep, origARP, origLocal }()

	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return []netutil.SweepResult{
			{IP: "10.0.0.5", TTL: 64},    // local: has an ARP entry -> real MAC/vendor
			{IP: "203.0.113.9", TTL: 54}, // routed: no ARP entry, outside local CIDR
		}
	}
	arpTable = func() map[string]string { return map[string]string{"10.0.0.5": "28:6f:b9:00:00:01"} }
	localNetworks = func() []string { return []string{"10.0.0.0/24"} }

	st := scanstate.New("full", "engine/test")
	caps := capabilities.Capabilities{ARPCache: true}
	if err := Run(context.Background(), st, caps, []string{"10.0.0.0/24"}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	m := marshalToMap(t, st)
	assets := assertStrictValid(t, m)
	if len(assets) == 0 {
		t.Fatal("assets is empty, want a populated payload for the DISC-05 gate")
	}

	// Every asset must carry non-null required containers and asset_type unknown.
	byID := map[string]map[string]any{}
	for _, raw := range assets {
		a := raw.(map[string]any)
		byID[a["external_id"].(string)] = a

		if _, ok := a["services"].([]any); !ok {
			t.Errorf("asset %v services is not a JSON list (got %T) — must be [] not null", a["external_id"], a["services"])
		}
		if _, ok := a["network_aliases"].([]any); !ok {
			t.Errorf("asset %v network_aliases is not a JSON list (got %T) — must be [] not null", a["external_id"], a["network_aliases"])
		}
		ce, ok := a["classification_evidence"].(map[string]any)
		if !ok {
			t.Fatalf("asset %v classification_evidence missing (got %T) — every asset carries it", a["external_id"], a["classification_evidence"])
		}
		if ce["asset_type"] != assetTypeUnknown {
			t.Errorf("asset %v asset_type = %v, want %q (D-02)", a["external_id"], ce["asset_type"], assetTypeUnknown)
		}
		if a["asset_type"] != assetTypeUnknown {
			t.Errorf("asset %v top-level asset_type = %v, want %q (D-02)", a["external_id"], a["asset_type"], assetTypeUnknown)
		}
		if _, ok := ce["evidence"].(map[string]any); !ok {
			t.Errorf("asset %v classification evidence is not a JSON object (got %T) — must be {} not null", a["external_id"], ce["evidence"])
		}
		if _, ok := ce["security_flags"].([]any); !ok {
			t.Errorf("asset %v security_flags is not a JSON list (got %T) — must be [] not null", a["external_id"], ce["security_flags"])
		}
		if a["managed"] != false || a["internet_facing"] != false {
			t.Errorf("asset %v managed=%v internet_facing=%v, want both false", a["external_id"], a["managed"], a["internet_facing"])
		}
	}

	// Local host: real MAC + vendor.
	local, ok := byID["mac:28:6f:b9:00:00:01"]
	if !ok {
		t.Fatalf("local host not re-keyed to mac:<mac>; ids=%v", keysOf(byID))
	}
	if local["mac_address"] != "28:6f:b9:00:00:01" {
		t.Errorf("local mac_address = %v, want 28:6f:b9:00:00:01", local["mac_address"])
	}
	if v, _ := local["mac_vendor"].(string); v == "" || v == macVendorNotOnLocalSegment {
		t.Errorf("local mac_vendor = %q, want a real OUI vendor", v)
	}

	// Routed host: null MAC, sentinel vendor, l2_segment=routed evidence.
	routed, ok := byID["ip:203.0.113.9"]
	if !ok {
		t.Fatalf("routed host missing; ids=%v", keysOf(byID))
	}
	if routed["mac_address"] != nil {
		t.Errorf("routed mac_address = %v, want null", routed["mac_address"])
	}
	if routed["mac_vendor"] != macVendorNotOnLocalSegment {
		t.Errorf("routed mac_vendor = %v, want sentinel %q", routed["mac_vendor"], macVendorNotOnLocalSegment)
	}
	rce := routed["classification_evidence"].(map[string]any)
	rev := rce["evidence"].(map[string]any)
	if rev[evidenceKeyL2Segment] != evidenceValueRouted {
		t.Errorf("routed evidence[%q] = %v, want %q", evidenceKeyL2Segment, rev[evidenceKeyL2Segment], evidenceValueRouted)
	}
}

// TestDetectDegrade proves ENG-06 graceful degradation through the REAL sweep:
// with a fully-degraded capability set (no ICMP socket, no system ping) the
// sweep has no viable probe and yields zero hosts, so Run returns nil and the
// payload is still strict-valid v6 with assets == []. It deliberately does not
// override sweepHosts, so the real netutil.Sweep + capability selection runs.
func TestDetectDegrade(t *testing.T) {
	if sweepHosts == nil {
		t.Fatal("sweepHosts seam is nil")
	}
	st := scanstate.New("full", "engine/test")
	// TEST-NET-1 scope is never actually probed: a nil capability set makes the
	// pinger selection return no probe, so the sweep short-circuits to zero.
	err := Run(context.Background(), st, capabilities.Capabilities{}, []string{"192.0.2.0/30"})
	if err != nil {
		t.Fatalf("fully-degraded Run returned %v, want nil", err)
	}
	assets := assertStrictValid(t, marshalToMap(t, st))
	if len(assets) != 0 {
		t.Fatalf("fully-degraded run produced %d assets, want 0", len(assets))
	}
}

// TestEnrichNetBIOSUnitIDMAC proves the NetBIOS node-status unit ID fills the MAC
// only where the ARP cache gave none (macOS 27 hides the cache without
// administrator rights). An ARP MAC always wins, so Linux/Windows output is
// unchanged where ARP answered; a routed host keeps the DISC-03 null MAC and
// sentinel; the external id is not re-keyed for a self-reported MAC.
func TestEnrichNetBIOSUnitIDMAC(t *testing.T) {
	origR, origM, origN, origL := resolveRDNS, resolveMDNS, resolveNetBIOS, localNetworks
	defer func() { resolveRDNS, resolveMDNS, resolveNetBIOS, localNetworks = origR, origM, origN, origL }()
	resolveRDNS = func(context.Context, string, time.Duration) string { return "" }
	resolveMDNS = func(context.Context, string, time.Duration) string { return "" }
	localNetworks = func() []string { return []string{"10.0.0.0/24"} }
	resolveNetBIOS = func(_ context.Context, ip string, _ time.Duration) netutil.NetBIOSStatus {
		// Every host claims a MAC; only the eligible ones may take it.
		return netutil.NetBIOSStatus{Name: "WIN", MAC: "74:24:9f:00:00:07"}
	}

	arpMAC := "aa:bb:cc:00:00:01"
	arpVendor := "ARP Vendor"
	entries := map[string]hostEntry{
		"ip:10.0.0.7":    {ip: "10.0.0.7"},
		"mac:" + arpMAC:  {ip: "10.0.0.8", mac: &arpMAC, macVendor: &arpVendor},
		"ip:203.0.113.9": {ip: "203.0.113.9", routed: true},
		// Off every local segment but not marked routed: with the ARP cache
		// hidden, L2 enrichment never ran. Its unit ID is not L2 evidence.
		"ip:198.51.100.4": {ip: "198.51.100.4"},
	}
	enrichHostnames(context.Background(), entries)

	h := entries["ip:10.0.0.7"]
	if h.mac == nil || *h.mac != "74:24:9f:00:00:07" {
		t.Fatalf("no-ARP host mac = %v, want the NetBIOS unit id", h.mac)
	}
	if h.macVendor == nil || *h.macVendor != "TIBRO Corp." {
		t.Errorf("no-ARP host vendor = %v, want TIBRO Corp. (OUI 74249F)", h.macVendor)
	}
	if !h.macFromNetBIOS {
		t.Error("no-ARP host must record the MAC as NetBIOS self-reported")
	}
	a := buildAsset("ip:10.0.0.7", h)
	classifyAsset(&a, h)
	if a.ExternalID != "ip:10.0.0.7" {
		t.Errorf("external id = %q, want ip:10.0.0.7 (no re-key on a self-reported MAC)", a.ExternalID)
	}
	if got := a.Classification.Evidence[evidenceKeyMACSource]; got != evidenceValueMACNetBIOS {
		t.Errorf("evidence[%s] = %q, want %q", evidenceKeyMACSource, got, evidenceValueMACNetBIOS)
	}

	arp := entries["mac:"+arpMAC]
	if arp.mac == nil || *arp.mac != arpMAC || arp.macFromNetBIOS {
		t.Errorf("ARP host changed: mac=%v fromNetBIOS=%v, want ARP MAC kept", arp.mac, arp.macFromNetBIOS)
	}
	aa := buildAsset("mac:"+arpMAC, arp)
	classifyAsset(&aa, arp)
	if _, ok := aa.Classification.Evidence[evidenceKeyMACSource]; ok {
		t.Error("ARP-sourced MAC must not carry a mac_source evidence key (output unchanged)")
	}

	r := entries["ip:203.0.113.9"]
	if r.mac != nil || r.macFromNetBIOS {
		t.Errorf("routed host mac = %v, want nil (DISC-03 sentinel kept)", r.mac)
	}
	if off := entries["ip:198.51.100.4"]; off.mac != nil {
		t.Errorf("off-segment host mac = %v, want nil (unit ID used on local segments only)", off.mac)
	}
}

// TestEnrichLocalInterfaceMAC proves the own-interface fill: an own IP with no
// MAC takes its interface's MAC and OUI vendor and is re-keyed to mac:<mac>; a
// secondary own IP sharing that MAC keeps its ip: id (claimed-MAC guard); an ARP
// MAC is never overridden; a routed host keeps the DISC-03 null MAC; a host that
// is not this machine is untouched.
func TestEnrichLocalInterfaceMAC(t *testing.T) {
	arpMAC := "aa:bb:cc:00:00:01"
	arpVendor := "ARP Vendor"
	entries := map[string]hostEntry{
		"ip:10.0.0.30":   {ip: "10.0.0.30"},
		"ip:10.0.0.31":   {ip: "10.0.0.31"},
		"mac:" + arpMAC:  {ip: "10.0.0.32", mac: &arpMAC, macVendor: &arpVendor},
		"ip:203.0.113.9": {ip: "203.0.113.9", routed: true},
		"ip:10.0.0.40":   {ip: "10.0.0.40"},
	}
	own := map[string]string{
		"10.0.0.30":   "74:24:9f:00:00:30",
		"10.0.0.31":   "74:24:9f:00:00:30",
		"10.0.0.32":   "74:24:9f:00:00:32",
		"203.0.113.9": "74:24:9f:00:00:99",
	}
	enrichLocalMAC(entries, own)

	if _, ok := entries["ip:10.0.0.30"]; ok {
		t.Error("ip:10.0.0.30 still present, want it re-keyed to mac:74:24:9f:00:00:30")
	}
	h, ok := entries["mac:74:24:9f:00:00:30"]
	if !ok {
		t.Fatalf("mac:74:24:9f:00:00:30 missing; keys = %v", entryKeys(entries))
	}
	if h.ip != "10.0.0.30" || h.mac == nil || *h.mac != "74:24:9f:00:00:30" {
		t.Errorf("own host = ip %q mac %v, want 10.0.0.30 with its interface MAC", h.ip, h.mac)
	}
	if h.macVendor == nil || *h.macVendor != "TIBRO Corp." {
		t.Errorf("own host vendor = %v, want TIBRO Corp. (OUI 74249F)", h.macVendor)
	}
	if !h.macFromLocalInterface {
		t.Error("own host must record the MAC as taken from the local interface")
	}

	sec, ok := entries["ip:10.0.0.31"]
	if !ok {
		t.Fatalf("ip:10.0.0.31 missing (claimed-MAC guard must keep the secondary address); keys = %v", entryKeys(entries))
	}
	if sec.mac == nil || *sec.mac != "74:24:9f:00:00:30" || !sec.macFromLocalInterface {
		t.Errorf("secondary own IP mac = %v fromLocal = %v, want the shared MAC and the flag", sec.mac, sec.macFromLocalInterface)
	}

	arp := entries["mac:"+arpMAC]
	if arp.mac == nil || *arp.mac != arpMAC || arp.macFromLocalInterface {
		t.Errorf("ARP host changed: mac = %v fromLocal = %v, want the ARP MAC kept", arp.mac, arp.macFromLocalInterface)
	}
	if r := entries["ip:203.0.113.9"]; r.mac != nil || !r.routed || r.macFromLocalInterface {
		t.Errorf("routed host = mac %v routed %v, want a nil MAC and routed kept (DISC-03)", r.mac, r.routed)
	}
	if o := entries["ip:10.0.0.40"]; o.mac != nil || o.macFromLocalInterface {
		t.Errorf("non-own host mac = %v, want nil", o.mac)
	}

	a := buildAsset("mac:74:24:9f:00:00:30", h)
	classifyAsset(&a, h)
	if a.ExternalID != "mac:74:24:9f:00:00:30" {
		t.Errorf("external id = %q, want mac:74:24:9f:00:00:30", a.ExternalID)
	}
	if got := a.Classification.Evidence[evidenceKeyMACSource]; got != evidenceValueMACLocalInterface {
		t.Errorf("evidence[%s] = %q, want %q", evidenceKeyMACSource, got, evidenceValueMACLocalInterface)
	}
	if got := a.Classification.Evidence[evidenceKeyMACVendor]; got != "TIBRO Corp." {
		t.Errorf("evidence[%s] = %q, want TIBRO Corp.", evidenceKeyMACVendor, got)
	}
	aa := buildAsset("mac:"+arpMAC, arp)
	classifyAsset(&aa, arp)
	if _, ok := aa.Classification.Evidence[evidenceKeyMACSource]; ok {
		t.Error("ARP-sourced MAC must not carry a mac_source evidence key")
	}
}

// TestRunFillsOwnHostMAC proves the fill end to end through Run: the scanning
// machine's own IP, which is never in its own neighbour cache, comes out with
// its interface MAC, vendor and mac_source=local_interface whether or not the
// ARP cache is readable.
func TestRunFillsOwnHostMAC(t *testing.T) {
	origSweep, origARP, origLocal, origOwn := sweepHosts, arpTable, localNetworks, localInterfaceMACs
	defer func() {
		sweepHosts, arpTable, localNetworks, localInterfaceMACs = origSweep, origARP, origLocal, origOwn
	}()
	sweepHosts = func(context.Context, []string, capabilities.Capabilities, netutil.PingFunc) []netutil.SweepResult {
		return []netutil.SweepResult{{IP: "10.0.0.5", TTL: 64}, {IP: "10.0.0.30", TTL: 64}}
	}
	arpTable = func() map[string]string { return map[string]string{"10.0.0.5": "28:6f:b9:00:00:01"} }
	localNetworks = func() []string { return []string{"10.0.0.0/24"} }
	localInterfaceMACs = func() map[string]string { return map[string]string{"10.0.0.30": "74:24:9f:00:00:30"} }

	for _, tc := range []struct {
		name     string
		arpCache bool
	}{
		{"arp_cache_readable", true},
		{"arp_cache_hidden", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := scanstate.New("full", "engine/test")
			caps := capabilities.Capabilities{ARPCache: tc.arpCache}
			if err := Run(context.Background(), st, caps, []string{"10.0.0.0/24"}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			assets := assertStrictValid(t, marshalToMap(t, st))
			byID := map[string]map[string]any{}
			for _, a := range assets {
				am := a.(map[string]any)
				byID[am["external_id"].(string)] = am
			}

			own, ok := byID["mac:74:24:9f:00:00:30"]
			if !ok {
				t.Fatalf("own host asset missing; ids = %v", keysOf(byID))
			}
			if own["ip_address"] != "10.0.0.30" || own["mac_address"] != "74:24:9f:00:00:30" {
				t.Errorf("own host ip = %v mac = %v, want 10.0.0.30 / 74:24:9f:00:00:30", own["ip_address"], own["mac_address"])
			}
			if own["mac_vendor"] != "TIBRO Corp." {
				t.Errorf("own host mac_vendor = %v, want TIBRO Corp.", own["mac_vendor"])
			}
			if got := evidenceOf(t, own)["mac_source"]; got != "local_interface" {
				t.Errorf("own host evidence mac_source = %v, want local_interface", got)
			}

			if tc.arpCache {
				nb, ok := byID["mac:28:6f:b9:00:00:01"]
				if !ok {
					t.Fatalf("ARP host asset missing; ids = %v", keysOf(byID))
				}
				if _, has := evidenceOf(t, nb)["mac_source"]; has {
					t.Error("ARP-sourced asset must not carry mac_source")
				}
				return
			}
			nb, ok := byID["ip:10.0.0.5"]
			if !ok {
				t.Fatalf("ip:10.0.0.5 missing with the cache hidden; ids = %v", keysOf(byID))
			}
			if nb["mac_address"] != nil {
				t.Errorf("ip:10.0.0.5 mac_address = %v, want null with the cache hidden", nb["mac_address"])
			}
		})
	}
}

// evidenceOf returns an asset's classification_evidence.evidence map.
func evidenceOf(t *testing.T, a map[string]any) map[string]any {
	t.Helper()
	c, ok := a["classification_evidence"].(map[string]any)
	if !ok {
		t.Fatalf("classification_evidence missing on %v", a["external_id"])
	}
	ev, _ := c["evidence"].(map[string]any)
	return ev
}

// entryKeys lists a host set's ids for a failure message.
func entryKeys(entries map[string]hostEntry) []string {
	ks := make([]string, 0, len(entries))
	for k := range entries {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// TestRunScopeSelection proves an explicit scope wins over the local networks and
// that every segment of a multi-segment scope is swept. With no explicit scope the
// local networks are used.
func TestRunScopeSelection(t *testing.T) {
	origSweep, origARP, origLocal := sweepHosts, arpTable, localNetworks
	defer func() { sweepHosts, arpTable, localNetworks = origSweep, origARP, origLocal }()

	var swept []string
	sweepHosts = func(_ context.Context, cidrs []string, _ capabilities.Capabilities, _ netutil.PingFunc) []netutil.SweepResult {
		swept = cidrs
		return nil
	}
	arpTable = func() map[string]string { return map[string]string{} }
	localNetworks = func() []string { return []string{"198.51.100.0/24"} }

	for _, tc := range []struct {
		name  string
		cidrs []string
		want  []string
	}{
		{"explicit multi-segment", []string{"192.0.2.0/30", "203.0.113.0/30"}, []string{"192.0.2.0/30", "203.0.113.0/30"}},
		{"empty uses local networks", nil, []string{"198.51.100.0/24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swept = nil
			st := scanstate.New("full", "engine/test")
			if err := Run(context.Background(), st, capabilities.Capabilities{}, tc.cidrs); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !slices.Equal(swept, tc.want) {
				t.Fatalf("swept %v, want %v", swept, tc.want)
			}
		})
	}
}
