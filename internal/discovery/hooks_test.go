// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
	"github.com/59k-ai/cysec-scanner/payload"
)

// recorder collects observer callbacks for assertions.
type recorder struct {
	mu       sync.Mutex
	progress [][2]int
	hosts    []string
	assets   []payload.AssetItem
}

func (r *recorder) observer() *scanstate.Observer {
	return &scanstate.Observer{
		OnProgress: func(stage string, done, total int) {
			if stage != "discovery" {
				return
			}
			r.mu.Lock()
			r.progress = append(r.progress, [2]int{done, total})
			r.mu.Unlock()
		},
		OnHostSeen: func(ip string) {
			r.mu.Lock()
			r.hosts = append(r.hosts, ip)
			r.mu.Unlock()
		},
		OnAsset: func(a payload.AssetItem) {
			r.mu.Lock()
			r.assets = append(r.assets, a)
			r.mu.Unlock()
		},
	}
}

// TestDiscoveryReportsLiveProgress drives the REAL default sweep seam with an
// injected pinger (one RFC 5737 host replies) and proves progress reaches
// done == total, the live IP is reported as seen, the committed asset is
// observed, and the committed assets equal a run without an observer.
func TestDiscoveryReportsLiveProgress(t *testing.T) {
	origPing, origLocal := sweepPing, localNetworks
	defer func() { sweepPing, localNetworks = origPing, origLocal }()
	sweepPing = func(_ context.Context, ip string, _ time.Duration) (bool, int) {
		return ip == "192.0.2.1", 64
	}
	localNetworks = func() []string { return nil }
	scope := []string{"192.0.2.0/30"}

	rec := &recorder{}
	withObs := scanstate.New("full", "engine/test")
	withObs.SetObserver(rec.observer())
	if err := Run(context.Background(), withObs, capabilities.Capabilities{}, scope); err != nil {
		t.Fatalf("Run (observer): %v", err)
	}
	plain := scanstate.New("full", "engine/test")
	if err := Run(context.Background(), plain, capabilities.Capabilities{}, scope); err != nil {
		t.Fatalf("Run (plain): %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.progress) != 2 {
		t.Fatalf("progress calls = %v, want 2 (one per probed host)", rec.progress)
	}
	maxDone := 0
	for _, p := range rec.progress {
		if p[1] != 2 {
			t.Errorf("progress total = %d, want 2", p[1])
		}
		if p[0] > maxDone {
			maxDone = p[0]
		}
	}
	if maxDone != 2 {
		t.Errorf("final done = %d, want 2", maxDone)
	}
	if len(rec.hosts) != 1 || rec.hosts[0] != "192.0.2.1" {
		t.Errorf("host-seen = %v, want [192.0.2.1]", rec.hosts)
	}
	if len(rec.assets) != 1 || rec.assets[0].ExternalID != "ip:192.0.2.1" {
		t.Errorf("observed assets = %+v, want one ip:192.0.2.1", rec.assets)
	}

	a, _ := json.Marshal(withObs.Payload())
	b, _ := json.Marshal(plain.Payload())
	if string(a) != string(b) {
		t.Fatalf("payload differs with observer:\n%s\nvs\n%s", a, b)
	}
}
