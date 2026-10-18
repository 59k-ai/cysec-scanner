package discovery

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/netutil"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// marshalToMap round-trips the accumulator payload through JSON into a generic
// map, so a required slice emitted as JSON null (nil) is distinguishable from an
// empty literal [] (a non-nil []any) — the strict-v5 invariant.
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

// assertStrictValidV5 asserts schema_version 5 and that assets is a JSON list
// (never null).
func assertStrictValidV5(t *testing.T, m map[string]any) []any {
	t.Helper()
	if sv, _ := m["schema_version"].(float64); sv != 5 {
		t.Fatalf("schema_version = %v, want 5", m["schema_version"])
	}
	assets, ok := m["assets"].([]any)
	if !ok {
		t.Fatalf("assets is not a JSON list (got %T) — a null required slice is strict-invalid", m["assets"])
	}
	return assets
}

// TestTracerEndToEnd is the Phase-3 tracer: an injected-live host becomes exactly
// one strict-valid v5 asset in the accumulator, and the zero-live case still
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
	assets := assertStrictValidV5(t, m)
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
	assets2 := assertStrictValidV5(t, marshalToMap(t, st2))
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
	assets := assertStrictValidV5(t, marshalToMap(t, st))
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

// TestEnrichL2States proves the three distinct L2 states: a local host carries a
// real MAC + OUI vendor with a stabilized mac:<mac> identity and no classification
// evidence; a routed host carries a null MAC, the sentinel vendor, and an
// l2_segment=routed evidence key; a not-observed host (within a local segment but
// absent from the ARP cache) stays fully null with no l2_segment key.
func TestEnrichL2States(t *testing.T) {
	live := []netutil.SweepResult{
		{IP: "10.0.0.5", TTL: 64},    // local: has an ARP entry
		{IP: "203.0.113.9", TTL: 54}, // routed: no ARP entry, outside local CIDR
		{IP: "10.0.0.7", TTL: 64},    // not observed: in local CIDR, no ARP entry
	}
	arp := map[string]string{"10.0.0.5": "28:6f:b9:00:00:01"}
	assets := runWithL2(t, live, arp, []string{"10.0.0.0/24"})

	// Local host: re-keyed to mac:<mac>, real MAC + vendor, no classification.
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
	if local["classification_evidence"] != nil {
		t.Errorf("local host must carry no classification evidence, got %v", local["classification_evidence"])
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

	// Not-observed host: fully null, no l2_segment evidence key.
	notObs, ok := assets["ip:10.0.0.7"]
	if !ok {
		t.Fatalf("not-observed host missing; keys=%v", keysOf(assets))
	}
	if notObs["mac_address"] != nil || notObs["mac_vendor"] != nil {
		t.Errorf("not-observed host must be fully null, got mac=%v vendor=%v", notObs["mac_address"], notObs["mac_vendor"])
	}
	if notObs["classification_evidence"] != nil {
		t.Errorf("not-observed host must carry no l2_segment evidence, got %v", notObs["classification_evidence"])
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

// TestDetectDegrade proves ENG-06 graceful degradation through the REAL sweep:
// with a fully-degraded capability set (no ICMP socket, no system ping) the
// sweep has no viable probe and yields zero hosts, so Run returns nil and the
// payload is still strict-valid v5 with assets == []. It deliberately does not
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
	assets := assertStrictValidV5(t, marshalToMap(t, st))
	if len(assets) != 0 {
		t.Fatalf("fully-degraded run produced %d assets, want 0", len(assets))
	}
}
