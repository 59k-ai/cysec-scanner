// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package runstate

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/progress"
)

func testRun(id string) RunInfo {
	return RunInfo{RunID: id, Trigger: "manual", StartedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

// recv reads one item or fails after a timeout.
func recv(t *testing.T, s *Subscription) Item {
	t.Helper()
	select {
	case it, ok := <-s.C():
		if !ok {
			t.Fatal("subscription channel closed")
		}
		return it
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an item")
	}
	return Item{}
}

func TestSubscribeIdle(t *testing.T) {
	h := NewHub(HubOptions{})
	snap, sub := h.Subscribe()
	defer sub.Close()
	if snap.Run != nil || snap.LastSeq != -1 || len(snap.Items) != 0 {
		t.Fatalf("idle snapshot = %+v, want Run nil, LastSeq -1, no items", snap)
	}
	if h.Run() != nil || h.State() != nil {
		t.Fatal("idle hub reports a run")
	}
	if h.Status() != "idle" {
		t.Fatalf("Status = %q, want idle", h.Status())
	}
	// Events without an active run are dropped, not reduced.
	h.Publish(hostEv(0, "10.0.0.1", ""))
	if h.State() != nil {
		t.Fatal("event without a run was reduced")
	}
	if h.Dropped() != 1 {
		t.Fatalf("Dropped = %d, want 1", h.Dropped())
	}
	select {
	case it := <-sub.C():
		t.Fatalf("idle subscriber got %+v", it)
	default:
	}
}

func TestSubscribeSnapshotAtomic(t *testing.T) {
	const total = 20000
	const subs = 50
	h := NewHub(HubOptions{QueueSize: total + 16})
	h.Begin(testRun("r1"))

	// gates[k] is closed once k events have been published; each subscriber
	// waits on one gate so it joins at a random point of the stream.
	gates := make([]chan struct{}, total+1)
	targets := make([]int, subs)
	for i := range targets {
		targets[i] = rand.IntN(total + 1)
		if gates[targets[i]] == nil {
			gates[targets[i]] = make(chan struct{})
		}
	}
	open := func(k int) {
		if gates[k] != nil {
			close(gates[k])
		}
	}
	var wg sync.WaitGroup
	var subscribed sync.WaitGroup
	errs := make(chan error, subs)
	subscribed.Add(subs)
	for i := 0; i < subs; i++ {
		wg.Add(1)
		go func(n int, gate <-chan struct{}) {
			defer wg.Done()
			<-gate
			snap, sub := h.Subscribe()
			subscribed.Done()
			defer sub.Close()
			if snap.Run == nil || snap.Run.RunID != "r1" {
				errs <- fmt.Errorf("sub %d: snapshot run = %+v", n, snap.Run)
				return
			}
			for _, it := range snap.Items {
				if !it.Replay || it.Kind != ItemEvent {
					errs <- fmt.Errorf("sub %d: snapshot item not a replay event: %+v", n, it)
					return
				}
				if it.Event.Seq > snap.LastSeq {
					errs <- fmt.Errorf("sub %d: snapshot seq %d > LastSeq %d", n, it.Event.Seq, snap.LastSeq)
					return
				}
			}
			next := snap.LastSeq + 1
			timeout := time.NewTimer(20 * time.Second)
			defer timeout.Stop()
			for {
				select {
				case it, ok := <-sub.C():
					if !ok {
						errs <- fmt.Errorf("sub %d: channel closed (lagged) at seq %d", n, next)
						return
					}
					if it.Kind == ItemRunState {
						if it.State != "ended" {
							errs <- fmt.Errorf("sub %d: unexpected run state %q", n, it.State)
							return
						}
						if next != total {
							errs <- fmt.Errorf("sub %d: ended at next seq %d, want %d", n, next, total)
						}
						return
					}
					if it.Replay {
						errs <- fmt.Errorf("sub %d: live item marked replay", n)
						return
					}
					if it.Event.Seq != next {
						errs <- fmt.Errorf("sub %d: live seq %d, want %d", n, it.Event.Seq, next)
						return
					}
					next++
				case <-timeout.C:
					errs <- fmt.Errorf("sub %d: timed out at seq %d", n, next)
					return
				}
			}
		}(i, gates[targets[i]])
	}

	open(0)
	h.Publish(scanStartEv(0, "discovery", "port"))
	open(1)
	for seq := 1; seq < total; seq++ {
		if seq%3 == 0 {
			h.Publish(hostEv(seq, fmt.Sprintf("10.%d.%d.%d", seq>>16&255, seq>>8&255, seq&255), ""))
		} else {
			h.Publish(stageEv(seq, "port", seq, total))
		}
		open(seq + 1)
	}
	subscribed.Wait()
	h.End("shipped")
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSlowConsumer(t *testing.T) {
	const n = 1000
	h := NewHub(HubOptions{QueueSize: 8})
	h.Begin(testRun("r1"))
	_, stuck := h.Subscribe()
	defer stuck.Close()
	_, reader := h.Subscribe()
	defer reader.Close()

	var got atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for it := range reader.C() {
			if it.Kind == ItemEvent {
				got.Add(1)
			}
		}
	}()

	start := time.Now()
	for i := 0; i < n; i++ {
		h.Publish(stageEv(i, "port", i, n))
		// Pace the publisher on the reading subscriber only, so the test
		// proves the stuck one is dropped rather than racing the reader.
		deadline := time.Now().Add(time.Second)
		for got.Load() < int64(i+1) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Microsecond)
		}
	}
	if el := time.Since(start); el >= time.Second {
		t.Fatalf("publishing %d events took %v, want < 1s", n, el)
	}
	select {
	case <-stuck.Lagged():
	default:
		t.Fatal("stuck subscriber not marked lagged")
	}
	drained := 0
	for range stuck.C() {
		drained++
	}
	if drained > 8 {
		t.Fatalf("stuck subscriber drained %d items, want at most the queue size", drained)
	}
	if got.Load() != n {
		t.Fatalf("reader got %d events, want %d", got.Load(), n)
	}
	select {
	case <-reader.Lagged():
		t.Fatal("reading subscriber marked lagged")
	default:
	}
	reader.Close()
	<-done
	// Close after a lag drop is a no-op.
	stuck.Close()
}

func TestRunStateItems(t *testing.T) {
	h := NewHub(HubOptions{})
	_, sub := h.Subscribe()
	defer sub.Close()
	info := testRun("r1")
	info.Trigger = "schedule"
	h.Begin(info)

	it := recv(t, sub)
	if it.Kind != ItemRunState || it.State != "started" || it.RunID != "r1" ||
		it.Trigger != "schedule" || !it.StartedAt.Equal(info.StartedAt) {
		t.Fatalf("Begin item = %+v", it)
	}
	if h.Status() != "running" {
		t.Fatalf("Status = %q, want running", h.Status())
	}
	h.Publish(hostEv(0, "10.0.0.1", ""))
	if it = recv(t, sub); it.Kind != ItemEvent || it.Event.Seq != 0 || it.RunID != "r1" || it.Replay {
		t.Fatalf("event item = %+v", it)
	}
	h.SetState("stopping")
	if it = recv(t, sub); it.Kind != ItemRunState || it.State != "stopping" || it.RunID != "r1" {
		t.Fatalf("SetState item = %+v", it)
	}
	if h.Status() != "stopping" {
		t.Fatalf("Status = %q, want stopping", h.Status())
	}
	h.End("shipped")
	if it = recv(t, sub); it.Kind != ItemRunState || it.State != "ended" || it.Outcome != "shipped" || it.RunID != "r1" {
		t.Fatalf("End item = %+v", it)
	}
	if h.Run() != nil {
		t.Fatal("Run() not nil after End")
	}
	if h.Status() != "idle" {
		t.Fatalf("Status = %q, want idle", h.Status())
	}
	snap, sub2 := h.Subscribe()
	defer sub2.Close()
	if snap.Run != nil || len(snap.Items) != 0 || snap.LastSeq != -1 {
		t.Fatalf("snapshot after End = %+v", snap)
	}
	st := h.State()
	if st == nil {
		t.Fatal("State() nil after End")
	}
	if hosts, _ := st.Hosts(); len(hosts) != 1 || hosts[0].IP != "10.0.0.1" {
		t.Fatalf("ended run hosts = %+v", hosts)
	}
	// State returns a copy: changing it does not touch the hub.
	st.Apply(hostEv(1, "10.0.0.2", ""))
	if hosts, _ := h.State().Hosts(); len(hosts) != 1 {
		t.Fatal("State() is not a copy")
	}
	// Publishing after End is dropped.
	h.Publish(hostEv(1, "10.0.0.3", ""))
	if hosts, _ := h.State().Hosts(); len(hosts) != 1 {
		t.Fatal("event after End was reduced")
	}
}

func TestBeginResets(t *testing.T) {
	h := NewHub(HubOptions{})
	h.Begin(testRun("r1"))
	h.Publish(scanStartEv(0, "discovery", "port"))
	h.Publish(stageEv(1, "port", 3, 9))
	h.Publish(hostEv(2, "10.0.0.1", ""))
	h.End("shipped")

	h.Begin(testRun("r2"))
	snap, sub := h.Subscribe()
	defer sub.Close()
	if snap.Run == nil || snap.Run.RunID != "r2" {
		t.Fatalf("snapshot run = %+v, want r2", snap.Run)
	}
	if len(snap.Items) != 0 || snap.LastSeq != -1 {
		t.Fatalf("second run snapshot = %+v, want empty", snap)
	}
	st := h.State()
	if hosts, _ := st.Hosts(); len(hosts) != 0 {
		t.Fatalf("hosts carried over: %+v", hosts)
	}
	if name, _, _ := st.CurrentStage(); name != "" {
		t.Fatalf("stage carried over: %q", name)
	}
	// A Begin without an End also resets.
	h.Publish(hostEv(0, "10.0.0.9", ""))
	h.Begin(testRun("r3"))
	if hosts, _ := h.State().Hosts(); len(hosts) != 0 {
		t.Fatal("Begin without End kept hosts")
	}
}

func TestSubscribeFunc(t *testing.T) {
	h := NewHub(HubOptions{QueueSize: 8})
	h.Begin(testRun("r1"))
	h.Publish(scanStartEv(0, "discovery"))

	var mu sync.Mutex
	var fnItems []Item
	fnDone := make(chan struct{}, 64)
	stop := h.SubscribeFunc(func(it Item) {
		mu.Lock()
		fnItems = append(fnItems, it)
		mu.Unlock()
		fnDone <- struct{}{}
	})
	defer stop()
	_, ch := h.Subscribe()
	defer ch.Close()

	unblock := make(chan struct{})
	var blockedCalls atomic.Int64
	stopBlocked := h.SubscribeFunc(func(Item) {
		blockedCalls.Add(1)
		<-unblock
	})

	waitFn := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			select {
			case <-fnDone:
			case <-time.After(2 * time.Second):
				t.Fatal("fn not called")
			}
		}
	}
	// The snapshot item reaches the fn subscriber first.
	waitFn(1)

	var chItems []Item
	start := time.Now()
	for i := 1; i <= 40; i++ {
		h.Publish(hostEv(i, fmt.Sprintf("10.0.0.%d", i), ""))
		chItems = append(chItems, recv(t, ch))
		waitFn(1)
	}
	if el := time.Since(start); el >= time.Second {
		t.Fatalf("Publish blocked behind a stuck fn: %v", el)
	}

	mu.Lock()
	live := fnItems[1:]
	if !fnItems[0].Replay || fnItems[0].Event.Kind != progress.ScanStart {
		t.Errorf("fn first item = %+v, want the scan_start replay", fnItems[0])
	}
	if len(live) != len(chItems) {
		t.Fatalf("fn got %d live items, channel got %d", len(live), len(chItems))
	}
	for i := range live {
		if live[i].Event.Seq != chItems[i].Event.Seq || live[i].Kind != chItems[i].Kind {
			t.Fatalf("item %d differs: fn %+v channel %+v", i, live[i], chItems[i])
		}
	}
	mu.Unlock()

	if c := blockedCalls.Load(); c != 1 {
		t.Fatalf("blocked fn called %d times, want 1", c)
	}
	close(unblock)
	stopBlocked()
	stopBlocked() // idempotent
	time.Sleep(20 * time.Millisecond)
	if c := blockedCalls.Load(); c > 1+8 {
		t.Fatalf("lagged fn kept receiving: %d calls", c)
	}
}
