// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
)

// onlyDotOne replies for 192.0.2.1 and stays silent for every other host, with a
// deterministic TTL so Sweep and SweepObserved results are comparable.
func onlyDotOne(_ context.Context, ip string, _ time.Duration) (bool, int) {
	if ip == "192.0.2.1" {
		return true, 64
	}
	return false, 0
}

type obsCall struct {
	ip    string
	alive bool
	done  int
	total int
}

// TestSweepObservedReportsEveryProbe proves the observer sees each probed IP
// once, with total = enumerated hosts, done values covering 1..total exactly
// once, alive only for the replying host, and results equal to Sweep's.
func TestSweepObservedReportsEveryProbe(t *testing.T) {
	scope := []string{"192.0.2.0/30"} // .1 and .2 (network/broadcast skipped)
	var mu sync.Mutex
	var calls []obsCall
	obs := func(ip string, alive bool, done, total int) {
		mu.Lock()
		calls = append(calls, obsCall{ip, alive, done, total})
		mu.Unlock()
	}

	got := SweepObserved(context.Background(), scope, capabilities.Capabilities{}, onlyDotOne, obs)
	want := Sweep(context.Background(), scope, capabilities.Capabilities{}, onlyDotOne)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SweepObserved = %v, Sweep = %v; want identical", got, want)
	}

	total := len(enumerateHosts(scope))
	if total != 2 {
		t.Fatalf("enumerated %d hosts, want 2", total)
	}
	if len(calls) != total {
		t.Fatalf("observer called %d times, want %d", len(calls), total)
	}
	seenIP := map[string]bool{}
	var dones []int
	for _, c := range calls {
		if c.total != total {
			t.Errorf("call %+v total = %d, want %d", c, c.total, total)
		}
		if seenIP[c.ip] {
			t.Errorf("ip %s reported twice", c.ip)
		}
		seenIP[c.ip] = true
		if c.alive != (c.ip == "192.0.2.1") {
			t.Errorf("ip %s alive = %v", c.ip, c.alive)
		}
		dones = append(dones, c.done)
	}
	sort.Ints(dones)
	for i, d := range dones {
		if d != i+1 {
			t.Fatalf("done values = %v, want 1..%d each once", dones, total)
		}
	}
}

// TestSweepObservedConcurrentDoneUnique runs a wider sweep through the worker
// pool and checks that done values stay unique under concurrency.
func TestSweepObservedConcurrentDoneUnique(t *testing.T) {
	scope := []string{"192.0.2.0/24"}
	var mu sync.Mutex
	seen := map[int]int{}
	SweepObserved(context.Background(), scope, capabilities.Capabilities{}, onlyDotOne,
		func(_ string, _ bool, done, _ int) {
			mu.Lock()
			seen[done]++
			mu.Unlock()
		})
	total := len(enumerateHosts(scope))
	if len(seen) != total {
		t.Fatalf("distinct done values = %d, want %d", len(seen), total)
	}
	for d, n := range seen {
		if d < 1 || d > total || n != 1 {
			t.Fatalf("done %d seen %d times (range 1..%d)", d, n, total)
		}
	}
}

// TestSweepObservedNilObserver proves a nil observer is exactly Sweep.
func TestSweepObservedNilObserver(t *testing.T) {
	scope := []string{"192.0.2.0/30"}
	got := SweepObserved(context.Background(), scope, capabilities.Capabilities{}, onlyDotOne, nil)
	want := []SweepResult{{IP: "192.0.2.1", TTL: 64}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SweepObserved(nil obs) = %v, want %v", got, want)
	}
}
