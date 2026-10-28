// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

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

// fastTier lets only the worker pool shape concurrency so tests run instantly.
var fastTier = Tier{PPS: 1e9, Burst: 100000, Workers: 8, BackoffWindow: 500}

// openOn returns a probe that reports the listed ports open (with a text banner)
// on every host and refuses everything else.
func openOn(open ...int) func(context.Context, string, int, Tier) (probeOutcome, bannerResult) {
	set := map[int]bool{}
	for _, p := range open {
		set[p] = true
	}
	return func(_ context.Context, _ string, port int, _ Tier) (probeOutcome, bannerResult) {
		if set[port] {
			return outcomeOpen, bannerResult{Text: "SSH-2.0-OpenSSH_9.6"}
		}
		return outcomeRefused, bannerResult{}
	}
}

func swapProbe(t *testing.T, p func(context.Context, string, int, Tier) (probeOutcome, bannerResult)) {
	t.Helper()
	orig := probe
	probe = p
	t.Cleanup(func() { probe = orig })
}

// TestPerAssetFinalizeEquivalence proves the observer does not change the
// payload: identical seeded state + probe, run with and without an observer,
// marshal byte-identically.
func TestPerAssetFinalizeEquivalence(t *testing.T) {
	swapProbe(t, openOn(22, 80, 443))
	ports := []int{21, 22, 80, 443, 8080}
	run := func(withObs bool) []byte {
		st := scanstate.New("full", "engine/test")
		seedAsset(st, "192.0.2.1")
		seedAsset(st, "192.0.2.2")
		seedAsset(st, "192.0.2.3")
		if withObs {
			st.SetObserver(&scanstate.Observer{
				OnAsset:    func(payload.AssetItem) {},
				OnProgress: func(string, int, int) {},
			})
		}
		if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{Tier: fastTier, Ports: ports}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		b, err := json.Marshal(st.Payload())
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b := run(true), run(false)
	if string(a) != string(b) {
		t.Fatalf("payload differs with observer:\n%s\nvs\n%s", a, b)
	}
}

// TestProgressCountsWorkItems proves port progress counts host x port items:
// total == hosts*ports, final done == total, each done value exactly once.
func TestProgressCountsWorkItems(t *testing.T) {
	swapProbe(t, openOn(22))
	ports := []int{22, 80, 443}
	st := scanstate.New("full", "engine/test")
	seedAsset(st, "192.0.2.1")
	seedAsset(st, "192.0.2.2")
	var mu sync.Mutex
	seen := map[int]int{}
	totals := map[int]bool{}
	st.SetObserver(&scanstate.Observer{OnProgress: func(stage string, done, total int) {
		if stage != "port" {
			return
		}
		mu.Lock()
		seen[done]++
		totals[total] = true
		mu.Unlock()
	}})
	if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{Tier: fastTier, Ports: ports}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := 2 * len(ports)
	if len(totals) != 1 || !totals[want] {
		t.Fatalf("totals = %v, want only %d", totals, want)
	}
	if len(seen) != want {
		t.Fatalf("distinct done values = %d, want %d", len(seen), want)
	}
	for d := 1; d <= want; d++ {
		if seen[d] != 1 {
			t.Fatalf("done %d seen %d times, want 1", d, seen[d])
		}
	}
}

// TestAssetFinalizedBeforeStageEnd proves an asset whose items are all done is
// merged mid-stage: A's OnAsset (with services) arrives while B's dial is still
// blocked.
func TestAssetFinalizedBeforeStageEnd(t *testing.T) {
	release := make(chan struct{})
	swapProbe(t, func(ctx context.Context, host string, port int, _ Tier) (probeOutcome, bannerResult) {
		if host == "192.0.2.2" {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return outcomeRefused, bannerResult{}
		}
		return outcomeOpen, bannerResult{Text: "SSH-2.0-OpenSSH_9.6"}
	})
	st := scanstate.New("full", "engine/test")
	seedAsset(st, "192.0.2.1")
	seedAsset(st, "192.0.2.2")
	gotA := make(chan payload.AssetItem, 4)
	st.SetObserver(&scanstate.Observer{OnAsset: func(a payload.AssetItem) {
		if a.ExternalID == "ip:192.0.2.1" && len(a.Services) > 0 {
			gotA <- a
		}
	}})

	errc := make(chan error, 1)
	go func() {
		errc <- Run(context.Background(), st, capabilities.Capabilities{}, Options{Tier: fastTier, Ports: []int{22}})
	}()
	select {
	case a := <-gotA:
		if a.Services[0].Port != 22 {
			t.Errorf("A services = %+v, want port 22", a.Services)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("asset A was not finalized while B was still in flight")
	}
	close(release)
	if err := <-errc; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestCancelledStageStillFinalizesGatheredPorts cancels the stage after A's
// items complete and while B's are pending: A keeps its services and every
// asset is finalized at most once.
func TestCancelledStageStillFinalizesGatheredPorts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// B has two ports: the first is open, the second blocks until cancel, so B
	// gathered data but never reaches remaining==0 and is finalized post-Wait.
	swapProbe(t, func(ctx context.Context, host string, port int, _ Tier) (probeOutcome, bannerResult) {
		if host == "192.0.2.2" && port == 80 {
			<-ctx.Done()
			return outcomeTimeout, bannerResult{}
		}
		return outcomeOpen, bannerResult{Text: "SSH-2.0-OpenSSH_9.6"}
	})
	st := scanstate.New("full", "engine/test")
	seedAsset(st, "192.0.2.1")
	seedAsset(st, "192.0.2.2")
	var mu sync.Mutex
	finalCount := map[string]int{}
	st.SetObserver(&scanstate.Observer{
		OnAsset: func(a payload.AssetItem) {
			if len(a.Services) == 0 {
				return
			}
			mu.Lock()
			finalCount[a.ExternalID]++
			mu.Unlock()
		},
		OnProgress: func(stage string, done, total int) {
			// A's two items + B's port-22 item done: cancel while B:80 blocks.
			if stage == "port" && done == 3 {
				cancel()
			}
		},
	})
	if err := Run(ctx, st, capabilities.Capabilities{}, Options{Tier: fastTier, Ports: []int{22, 80}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	byID := map[string]payload.AssetItem{}
	for _, a := range st.Payload().Assets {
		byID[a.ExternalID] = a
	}
	if n := len(byID["ip:192.0.2.1"].Services); n != 2 {
		t.Errorf("A services = %d, want 2", n)
	}
	if n := len(byID["ip:192.0.2.2"].Services); n != 1 {
		t.Errorf("B services = %d, want 1 (gathered before cancel)", n)
	}
	mu.Lock()
	defer mu.Unlock()
	for id, n := range finalCount {
		if n != 1 {
			t.Errorf("asset %s finalized %d times, want 1", id, n)
		}
	}
	if len(finalCount) != 2 {
		t.Errorf("finalized assets = %v, want both", finalCount)
	}
}
