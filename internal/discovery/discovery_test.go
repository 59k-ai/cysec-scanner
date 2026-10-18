package discovery

import (
	"context"
	"encoding/json"
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
