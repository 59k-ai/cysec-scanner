// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package runstate

import (
	"sync"
	"time"

	"github.com/59k-ai/cysec-scanner/progress"
)

// DefaultQueueSize is the per-subscriber queue length. A subscriber that falls
// this many items behind is dropped.
const DefaultQueueSize = 1024

// RunInfo identifies the active run.
type RunInfo struct {
	RunID     string    `json:"run_id"`
	Trigger   string    `json:"trigger"`
	StartedAt time.Time `json:"started_at"`
}

// HubOptions tunes a Hub. Zero values select the defaults.
type HubOptions struct {
	QueueSize int // per-subscriber queue length; default DefaultQueueSize
	MaxHosts  int // hosts kept per run; default DefaultMaxHosts
}

// ItemKind tells what an Item carries.
type ItemKind int

const (
	// ItemEvent carries a progress event in Event.
	ItemEvent ItemKind = iota
	// ItemRunState carries a run lifecycle change in State (and Outcome).
	ItemRunState
)

// Item is one entry of a subscriber feed.
type Item struct {
	Kind  ItemKind
	RunID string

	// ItemEvent fields. Replay is true for snapshot items.
	Event  progress.Event
	Replay bool

	// ItemRunState fields. State is "started", "stopping" or "ended";
	// Outcome is set only on "ended".
	State     string
	Trigger   string
	StartedAt time.Time
	Outcome   string
}

// Snapshot is what a subscriber sees at the moment it joins. Run is nil when no
// run is active; LastSeq is -1 then. Every live ItemEvent that follows has a
// Seq greater than LastSeq.
type Snapshot struct {
	Run     *RunInfo
	Items   []Item
	LastSeq int
}

// Hub holds the state of the current run and fans published events out to
// subscribers. All methods are safe for concurrent use.
type Hub struct {
	queueSize int
	maxHosts  int

	mu       sync.Mutex
	run      *RunInfo
	stopping bool
	state    *RunState // current run, or the last one after End
	subs     map[*Subscription]struct{}
	dropped  int
}

// NewHub returns an idle Hub.
func NewHub(o HubOptions) *Hub {
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = DefaultMaxHosts
	}
	return &Hub{
		queueSize: o.QueueSize,
		maxHosts:  o.MaxHosts,
		subs:      make(map[*Subscription]struct{}),
	}
}

// Begin starts a new run with fresh state, replacing any previous run, and
// tells subscribers with a "started" item.
func (h *Hub) Begin(info RunInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	run := info
	h.run = &run
	h.stopping = false
	h.state = newRunState(h.maxHosts)
	h.fanout(Item{
		Kind:      ItemRunState,
		RunID:     info.RunID,
		State:     "started",
		Trigger:   info.Trigger,
		StartedAt: info.StartedAt,
	})
}

// Publish reduces ev into the run state and forwards it to every subscriber.
// It never blocks: a subscriber whose queue is full is dropped instead, so a
// stalled observer cannot slow the scan that produces the events. Events
// published while no run is active are dropped and counted (see Dropped).
func (h *Hub) Publish(ev progress.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run == nil {
		h.dropped++
		return
	}
	h.state.Apply(ev)
	h.fanout(Item{Kind: ItemEvent, RunID: h.run.RunID, Event: ev})
}

// SetState announces a lifecycle change of the active run; the host uses
// "stopping" after a cancel request. It is ignored when no run is active.
func (h *Hub) SetState(state string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run == nil {
		return
	}
	if state == "stopping" {
		h.stopping = true
	}
	h.fanout(h.runItem(state))
}

// End closes the active run with outcome and tells subscribers with an
// "ended" item. The reduced state stays readable through State until the next
// Begin. It is ignored when no run is active.
func (h *Hub) End(outcome string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run == nil {
		return
	}
	it := h.runItem("ended")
	it.Outcome = outcome
	h.run = nil
	h.stopping = false
	h.fanout(it)
}

func (h *Hub) runItem(state string) Item {
	return Item{
		Kind:      ItemRunState,
		RunID:     h.run.RunID,
		State:     state,
		Trigger:   h.run.Trigger,
		StartedAt: h.run.StartedAt,
	}
}

// Run returns a copy of the active run, or nil when idle.
func (h *Hub) Run() *RunInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run == nil {
		return nil
	}
	r := *h.run
	return &r
}

// Status returns "idle", "running" or "stopping".
func (h *Hub) Status() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.run == nil:
		return "idle"
	case h.stopping:
		return "stopping"
	default:
		return "running"
	}
}

// State returns a copy of the current run's state, or of the last run's after
// End; nil before the first Begin.
func (h *Hub) State() *RunState {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.state == nil {
		return nil
	}
	return h.state.clone()
}

// Dropped returns how many events were published while no run was active.
func (h *Hub) Dropped() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dropped
}

// fanout must be called with h.mu held.
func (h *Hub) fanout(it Item) {
	for s := range h.subs {
		select {
		case s.ch <- it:
		default:
			// Full queue: drop this subscriber rather than wait for it.
			delete(h.subs, s)
			close(s.done)
			close(s.lagged)
			close(s.ch)
		}
	}
}

// Subscription is a bounded live feed. C delivers items in publish order. When
// the subscriber falls a full queue behind, Lagged is closed and then C is
// closed; the subscriber must resubscribe to get a fresh snapshot.
type Subscription struct {
	h      *Hub
	ch     chan Item
	lagged chan struct{}
	done   chan struct{} // closed on Close or lag drop
}

// Subscribe returns the snapshot of the active run and a live feed of
// everything published after it. The snapshot is taken and the feed is
// registered under the lock Publish holds, so the feed starts with exactly the
// event after Snapshot.LastSeq: no event is missed and none is repeated.
func (h *Hub) Subscribe() (Snapshot, *Subscription) {
	h.mu.Lock()
	defer h.mu.Unlock()
	snap := Snapshot{LastSeq: -1}
	if h.run != nil {
		r := *h.run
		snap.Run = &r
		snap.LastSeq = h.state.LastSeq()
		rep := h.state.Replay()
		snap.Items = make([]Item, len(rep))
		for i, ev := range rep {
			snap.Items[i] = Item{Kind: ItemEvent, RunID: r.RunID, Event: ev, Replay: true}
		}
	}
	s := &Subscription{
		h:      h,
		ch:     make(chan Item, h.queueSize),
		lagged: make(chan struct{}),
		done:   make(chan struct{}),
	}
	h.subs[s] = struct{}{}
	return snap, s
}

// C returns the live feed. It is closed after Close or after a lag drop.
func (s *Subscription) C() <-chan Item { return s.ch }

// Lagged is closed when the subscription was dropped for falling behind.
func (s *Subscription) Lagged() <-chan struct{} { return s.lagged }

// Close ends the subscription and closes C. It is safe to call more than once
// and after a lag drop.
func (s *Subscription) Close() {
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	if _, ok := s.h.subs[s]; !ok {
		return
	}
	delete(s.h.subs, s)
	close(s.done)
	close(s.ch)
}

// SubscribeFunc runs fn on its own goroutine for each snapshot item and then
// each live item, for observers in the same process. It uses an ordinary
// bounded subscription, so a slow fn is dropped like any slow subscriber and is
// not called again after the drop or after stop returns, apart from a call
// already in progress. stop ends the feed; it does not wait for a
// call of fn that is already running, so it is safe to call from inside fn.
func (h *Hub) SubscribeFunc(fn func(Item)) (stop func()) {
	snap, sub := h.Subscribe()
	go func() {
		for _, it := range snap.Items {
			if sub.ended() {
				return
			}
			fn(it)
		}
		for it := range sub.ch {
			if sub.ended() {
				return
			}
			fn(it)
		}
	}()
	return sub.Close
}

func (s *Subscription) ended() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
