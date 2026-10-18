// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// marshalToMap round-trips the accumulator payload through JSON so a required
// slice emitted as JSON null is distinguishable from an empty literal [] — the
// strict-v5 invariant. Mirrors the discovery stage's test helper.
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

// assertStrictValidV6 asserts schema_version 6 and that assets is a JSON list.
func assertStrictValidV6(t *testing.T, m map[string]any) []any {
	t.Helper()
	if sv, _ := m["schema_version"].(float64); sv != 6 {
		t.Fatalf("schema_version = %v, want 6", m["schema_version"])
	}
	assets, ok := m["assets"].([]any)
	if !ok {
		t.Fatalf("assets is not a JSON list (got %T) — a null required slice is strict-invalid", m["assets"])
	}
	return assets
}

// seedAsset adds one discovery-shaped asset (IP-keyed, empty services, a routed
// l2_segment evidence key) so a merge can be checked for preservation.
func seedAsset(st *scanstate.ScanState, ip string) {
	addr := ip
	st.AddAsset(payload.AssetItem{
		ExternalID:     "ip:" + ip,
		IPAddress:      &addr,
		AssetType:      "unknown",
		Services:       []payload.ServiceItem{},
		NetworkAliases: []payload.NetworkAliasItem{},
		Classification: &payload.ClassificationEvidence{
			AssetType:     "unknown",
			Confidence:    0.1,
			RuleName:      "discovery-evidence-v1",
			Evidence:      map[string]string{"l2_segment": "routed"},
			SecurityFlags: []string{},
		},
	})
}

// TestTracerEndToEnd proves the whole vertical slice over the real connect+banner
// path: one open loopback port becomes exactly one strict-valid v5 ServiceItem
// with a merged classification that preserves discovery's evidence; and a
// zero-asset run mutates nothing and still yields a strict-valid payload.
func TestTracerEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello-banner\r\n"))
			_ = conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	st := scanstate.New("full", "engine/test")
	seedAsset(st, "127.0.0.1")
	opts := Options{Tier: ResolveTier("polite"), Ports: []int{port}}
	if err := Run(context.Background(), st, capabilities.Capabilities{}, opts); err != nil {
		t.Fatalf("Run (live): %v", err)
	}

	assets := st.Assets()
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	a := assets[0]
	if len(a.Services) != 1 {
		t.Fatalf("got %d services, want exactly 1", len(a.Services))
	}
	svc := a.Services[0]
	if svc.Port != port {
		t.Errorf("service port = %d, want %d", svc.Port, port)
	}
	if svc.Protocol != "tcp" {
		t.Errorf("service protocol = %q, want tcp", svc.Protocol)
	}
	if svc.ExposureLevel != "internal" {
		t.Errorf("service exposure_level = %q, want internal", svc.ExposureLevel)
	}
	if a.Classification == nil || a.Classification.Evidence["l2_segment"] != "routed" {
		t.Errorf("merge did not preserve pre-existing evidence l2_segment=routed: %+v", a.Classification)
	}

	m := marshalToMap(t, st)
	outAssets := assertStrictValidV6(t, m)
	first := outAssets[0].(map[string]any)
	if _, ok := first["services"].([]any); !ok {
		t.Errorf("asset services is not a JSON list (got %T)", first["services"])
	}

	// Zero-asset run: nil, no mutation, no hang.
	st2 := scanstate.New("full", "engine/test")
	if err := Run(context.Background(), st2, capabilities.Capabilities{}, opts); err != nil {
		t.Fatalf("Run (zero): %v", err)
	}
	if assets2 := assertStrictValidV6(t, marshalToMap(t, st2)); len(assets2) != 0 {
		t.Fatalf("zero-asset run produced %d assets, want 0", len(assets2))
	}
}

// TestRunFeedsOutcomeWindow proves Run records every probe outcome into one
// shared window and invokes the adaptive-backoff hook — the seam a later plan
// fills. The probe seam returns a known mix across ports; the adjustRate seam is
// swapped for a recorder capturing the window and the call count.
func TestRunFeedsOutcomeWindow(t *testing.T) {
	origProbe, origAdjust := probe, adjustRate
	defer func() { probe, adjustRate = origProbe, origAdjust }()

	probe = func(_ context.Context, _ string, port int, _ Tier) (probeOutcome, bannerResult) {
		switch port {
		case 1:
			return outcomeOpen, bannerResult{Text: "x"}
		case 2:
			return outcomeRefused, bannerResult{}
		case 3:
			return outcomeTimeout, bannerResult{}
		default:
			return outcomeError, bannerResult{}
		}
	}

	var mu sync.Mutex
	var calls int
	var captured *outcomeWindow
	adjustRate = func(_ Tier, _ *rate.Limiter, w *outcomeWindow) {
		mu.Lock()
		calls++
		captured = w
		mu.Unlock()
	}

	st := scanstate.New("full", "engine/test")
	seedAsset(st, "127.0.0.1")
	tier := Tier{PPS: 100000, Burst: 1000, Workers: 8, BackoffWindow: 50}
	if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{Tier: tier, Ports: []int{1, 2, 3, 4}}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if calls < 1 {
		t.Fatalf("adjustRate invoked %d times, want >=1", calls)
	}
	if captured == nil {
		t.Fatal("adjustRate never captured the window")
	}
	open, refused, timeout, errored, total := captured.counts()
	if open != 1 || refused != 1 || timeout != 1 || errored != 1 || total != 4 {
		t.Fatalf("window counts = open%d refused%d timeout%d errored%d total%d, want 1/1/1/1/4",
			open, refused, timeout, errored, total)
	}
}

// netTimeout is a synthetic net.Error whose Timeout() is true.
type netTimeout struct{}

func (netTimeout) Error() string   { return "i/o timeout" }
func (netTimeout) Timeout() bool   { return true }
func (netTimeout) Temporary() bool { return true }

// TestClassifyDialError proves the graded outcome mapping: a fast RST is refused
// (on POSIX via ECONNREFUSED and on Windows via WSAECONNREFUSED, including when
// wrapped in an *os.SyscallError chain the way net.Dialer surfaces it), a
// deadline / net-timeout is timeout, and anything else is error. The synthetic
// syscall.Errno(10061) case proves the Windows path deterministically without a
// Windows host — errors.Is(err, syscall.ECONNREFUSED) is false for it, so only
// the errno comparison in isConnRefused grades it refused.
func TestClassifyDialError(t *testing.T) {
	wsarefused := syscall.Errno(10061) // WSAECONNREFUSED, the Windows refused-connect code
	cases := []struct {
		name string
		err  error
		want probeOutcome
	}{
		{"refused", syscall.ECONNREFUSED, outcomeRefused},
		{"refused-wrapped", &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}, outcomeRefused},
		{"windows-refused", wsarefused, outcomeRefused},
		{"windows-refused-wrapped", &os.SyscallError{Syscall: "connect", Err: wsarefused}, outcomeRefused},
		{"ctx-deadline", context.DeadlineExceeded, outcomeTimeout},
		{"os-deadline", os.ErrDeadlineExceeded, outcomeTimeout},
		{"net-timeout", netTimeout{}, outcomeTimeout},
		{"generic", errors.New("boom"), outcomeError},
		{"nil", nil, outcomeOpen},
	}
	for _, tc := range cases {
		if got := classifyDialError(tc.err); got != tc.want {
			t.Errorf("%s: classifyDialError = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestAggregateHints proves ascending-port precedence: the lowest-numbered open
// port supplying a non-empty hint wins, independently for product and OS cue.
func TestAggregateHints(t *testing.T) {
	hint := func(p int) (string, string) {
		switch p {
		case 22:
			return "", "openssh-os"
		case 80:
			return "nginx", ""
		case 443:
			return "apache", "iis-os"
		}
		return "", ""
	}
	// Intentionally unsorted input to prove aggregateHints sorts it.
	ph, oc := aggregateHints([]int{443, 80, 22}, hint)
	if ph != "nginx" {
		t.Errorf("productHint = %q, want nginx (lowest non-empty is port 80)", ph)
	}
	if oc != "openssh-os" {
		t.Errorf("osCue = %q, want openssh-os (lowest non-empty is port 22)", oc)
	}
}

// TestServiceIdentityProvenance proves the D-08 labels are written only for a
// service that carries a parsed identity.
func TestServiceIdentityProvenance(t *testing.T) {
	prod := "nginx"
	services := []payload.ServiceItem{
		{Port: 80, Product: &prod},
		{Port: 22},
	}
	out := serviceIdentityProvenance(services)
	if out["service_identity_source:80"] != "port-banner-v1" {
		t.Errorf("source:80 = %q, want port-banner-v1", out["service_identity_source:80"])
	}
	if out["service_identity_confidence:80"] != "low" {
		t.Errorf("confidence:80 = %q, want low", out["service_identity_confidence:80"])
	}
	if _, ok := out["service_identity_source:22"]; ok {
		t.Errorf("port 22 (nil identity) must not get a provenance label")
	}
	if len(out) != 2 {
		t.Errorf("provenance map size = %d, want 2", len(out))
	}
}

// TestWorkerPoolBound enforces the PORT-02 worker-pool concurrency bound: the
// peak number of concurrent in-flight probes must never exceed the tier's Workers
// bound. PPS/Burst are set high so only the worker-pool semaphore bounds
// concurrency, making this a deterministic check that fails if the bound
// regresses.
func TestWorkerPoolBound(t *testing.T) {
	origProbe := probe
	defer func() { probe = origProbe }()

	const workers = 4
	var inFlight, peak int32
	probe = func(_ context.Context, _ string, _ int, _ Tier) (probeOutcome, bannerResult) {
		cur := atomic.AddInt32(&inFlight, 1)
		defer atomic.AddInt32(&inFlight, -1)
		for {
			p := atomic.LoadInt32(&peak)
			if cur <= p || atomic.CompareAndSwapInt32(&peak, p, cur) {
				break
			}
		}
		time.Sleep(3 * time.Millisecond)
		return outcomeRefused, bannerResult{}
	}

	ports := make([]int, 0, 200)
	for i := 1; i <= 200; i++ {
		ports = append(ports, i)
	}
	st := scanstate.New("full", "engine/test")
	seedAsset(st, "127.0.0.1")
	tier := Tier{PPS: 1e9, Burst: 100000, Workers: workers, BackoffWindow: 500}
	if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{Tier: tier, Ports: ports}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := atomic.LoadInt32(&peak); got > workers {
		t.Fatalf("peak concurrent probes = %d, want <= %d (worker-pool bound regressed)", got, workers)
	}
	if got := atomic.LoadInt32(&peak); got == 0 {
		t.Fatal("no probes ran — the test did not exercise the pool")
	}
}
