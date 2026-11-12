// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// host.go composes the base control and observe host: the standard methods
// (status.get, run.start, run.cancel, events.subscribe) on top of a Server, a
// host-supplied RunController that owns what a "run" is, and a runstate.Hub
// whose snapshot-then-live feed is streamed to every subscribed session.
//
// A host adds its own methods with Host.Handle and its own status fields
// through HostOptions.StatusExt; neither needs a protocol change. The
// standard methods cannot be overridden.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/59k-ai/cysec-scanner/ipc/runstate"
	"github.com/59k-ai/cysec-scanner/progress"
)

// RunStatus is what a RunController reports for status.get. State is "idle",
// "running" or "stopping"; an empty State is filled from the Hub, and so is a
// nil Run while the Hub has an active run. NextRunAt is the next scheduled
// start, or nil when the host has no schedule.
type RunStatus struct {
	State     string
	Run       *runstate.RunInfo
	NextRunAt *time.Time
}

// RunController is the host-defined notion of a run. The Host calls it for
// run.start, run.cancel and status.get; the controller reports progress by
// driving the Hub (Begin, Publish, SetState, End).
//
// ctx bounds the call only: it ends with the requesting session, so a
// controller must not tie the run's lifetime to it. peer is the kernel
// identity of the requesting session, for the controller's own policy.
//
// Start receives the raw request params unchanged. Errors map to the wire as
// follows: ErrRunInProgress to CodeRunInProgress, ErrNotRunning to
// CodeNotRunning, ErrRunMismatch to CodeRunMismatch, an *Error verbatim (for
// example CodeInvalidParams for params the host does not accept), anything
// else to CodeInternal with a fixed message.
type RunController interface {
	Start(ctx context.Context, params json.RawMessage, peer Peer) (runID string, err error)
	Cancel(ctx context.Context, runID string, peer Peer) error
	Status() RunStatus
}

// ErrRunInProgress refuses a start while RunID is active. It may be returned
// as a value or a pointer, and may be wrapped.
type ErrRunInProgress struct {
	RunID string
}

func (e ErrRunInProgress) Error() string { return "ipc: run already in progress: " + e.RunID }

var (
	// ErrNotRunning refuses a cancel when no run is active.
	ErrNotRunning = errors.New("ipc: no run in progress")
	// ErrRunMismatch refuses a cancel whose run id is not the active run.
	ErrRunMismatch = errors.New("ipc: run id does not match")
)

// HostOptions configure a Host. Server, Hub and Runs are required.
type HostOptions struct {
	Server *Server
	Hub    *runstate.Hub
	Runs   RunController
	// StatusExt returns the host-defined "ext" object of status.get. A nil
	// func or a nil result is sent as {}.
	StatusExt func() any
	// Logger receives the audit lines. Default slog.Default().
	Logger *slog.Logger
}

// Wire shapes of the standard methods and notifications.
type (
	// RunRef names a run on the wire. StartedAt is RFC 3339 in UTC.
	RunRef struct {
		RunID     string `json:"run_id"`
		Trigger   string `json:"trigger"`
		StartedAt string `json:"started_at"`
	}
	// StatusResult answers status.get.
	StatusResult struct {
		State     string          `json:"state"`
		Run       *RunRef         `json:"run"`
		NextRunAt *string         `json:"next_run_at"`
		Ext       json.RawMessage `json:"ext"`
	}
	// StartResult answers run.start.
	StartResult struct {
		RunID string `json:"run_id"`
	}
	// CancelParams are the run.cancel params.
	CancelParams struct {
		RunID string `json:"run_id"`
	}
	// CancelResult answers run.cancel.
	CancelResult struct {
		Accepted bool `json:"accepted"`
	}
	// SubscribeResult answers events.subscribe. LastSeq is -1 when idle.
	SubscribeResult struct {
		Run     *RunRef `json:"run"`
		LastSeq int     `json:"last_seq"`
	}
	// ProgressParams carry one progress event; Replay marks snapshot items.
	ProgressParams struct {
		RunID  string         `json:"run_id"`
		Replay bool           `json:"replay"`
		Event  progress.Event `json:"event"`
	}
	// SnapshotDoneParams end the replay. Live events that follow have a seq
	// greater than LastSeq.
	SnapshotDoneParams struct {
		RunID   *string `json:"run_id"`
		LastSeq int     `json:"last_seq"`
	}
	// RunStateParams announce a run lifecycle change. Outcome is set only on
	// "ended".
	RunStateParams struct {
		RunID     string `json:"run_id"`
		State     string `json:"state"`
		Trigger   string `json:"trigger"`
		StartedAt string `json:"started_at"`
		Outcome   string `json:"outcome,omitempty"`
	}
)

var standardMethods = []string{MethodStatusGet, MethodRunStart, MethodRunCancel, MethodEventsSubscribe}

// Host serves the standard methods for one Hub and one RunController.
type Host struct {
	o   HostOptions
	srv *Server
	log *slog.Logger

	mu   sync.Mutex
	subs map[*Session]*pump
}

// pump streams one subscription to one session.
type pump struct {
	sub  *runstate.Subscription
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func (p *pump) halt() {
	p.once.Do(func() { close(p.stop) })
	p.sub.Close()
}

// NewHost registers the standard methods on o.Server.
func NewHost(o HostOptions) (*Host, error) {
	if o.Server == nil || o.Hub == nil || o.Runs == nil {
		return nil, errors.New("ipc: Server, Hub and Runs are required")
	}
	for _, m := range standardMethods {
		if o.Server.handler(m) != nil {
			return nil, fmt.Errorf("ipc: %q is already registered on the server", m)
		}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	h := &Host{o: o, srv: o.Server, log: o.Logger, subs: make(map[*Session]*pump)}
	o.Server.Handle(MethodStatusGet, h.statusGet)
	o.Server.Handle(MethodRunStart, h.runStart)
	o.Server.Handle(MethodRunCancel, h.runCancel)
	o.Server.Handle(MethodEventsSubscribe, h.eventsSubscribe)
	return h, nil
}

// Handle registers a host-specific method. It panics when method is one of
// the standard methods, because silently replacing one would change the
// contract every client relies on.
func (h *Host) Handle(method string, fn HandlerFunc) {
	for _, m := range standardMethods {
		if m == method {
			panic(fmt.Sprintf("ipc: %q is a standard host method and cannot be overridden", method))
		}
	}
	h.srv.Handle(method, fn)
}

// Serve accepts sessions on l; see Server.Serve.
func (h *Host) Serve(l net.Listener) error { return h.srv.Serve(l) }

// Shutdown closes every session and stops accepting; see Server.Shutdown.
func (h *Host) Shutdown(ctx context.Context) error { return h.srv.Shutdown(ctx) }

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func runRef(r *runstate.RunInfo) *RunRef {
	if r == nil {
		return nil
	}
	return &RunRef{RunID: r.RunID, Trigger: r.Trigger, StartedAt: rfc3339(r.StartedAt)}
}

func (h *Host) statusGet(context.Context, *Session, json.RawMessage) (any, error) {
	st := h.o.Runs.Status()
	if st.State == "" {
		st.State = h.o.Hub.Status()
	}
	if st.Run == nil && st.State != "idle" {
		st.Run = h.o.Hub.Run()
	}
	res := StatusResult{State: st.State, Run: runRef(st.Run), Ext: json.RawMessage("{}")}
	if st.NextRunAt != nil {
		s := rfc3339(*st.NextRunAt)
		res.NextRunAt = &s
	}
	if h.o.StatusExt != nil {
		if ext := h.o.StatusExt(); ext != nil {
			b, err := json.Marshal(ext)
			if err != nil {
				return nil, err
			}
			if string(b) != "null" {
				res.Ext = b
			}
		}
	}
	return res, nil
}

// runError maps controller errors to wire errors. It returns the error to
// send and the run id carried by a run-in-progress refusal.
func runError(err error) (error, string) {
	var e *Error
	var v ErrRunInProgress
	var p *ErrRunInProgress
	switch {
	case errors.As(err, &e):
		return e, ""
	case errors.As(err, &v):
		return runInProgress(v.RunID), v.RunID
	case errors.As(err, &p) && p != nil:
		return runInProgress(p.RunID), p.RunID
	case errors.Is(err, ErrNotRunning):
		return &Error{Code: CodeNotRunning, Message: "no run in progress"}, ""
	case errors.Is(err, ErrRunMismatch):
		return &Error{Code: CodeRunMismatch, Message: "run id does not match"}, ""
	}
	return err, ""
}

func runInProgress(runID string) *Error {
	return &Error{Code: CodeRunInProgress, Message: "run already in progress", Data: map[string]string{"run_id": runID}}
}

func errCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}

// audit writes one control-verb line: the verb, the run, the result code (0
// on success) and the session peer.
func (h *Host) audit(msg string, s *Session, runID string, err error) {
	attrs := []any{"run_id", runID, "code", 0}
	if err != nil {
		attrs[3] = errCode(err)
	}
	attrs = append(attrs, s.Peer().LogAttrs()...)
	h.log.Info(msg, attrs...)
}

func (h *Host) runStart(ctx context.Context, s *Session, params json.RawMessage) (any, error) {
	runID, err := h.o.Runs.Start(ctx, params, s.Peer())
	if err != nil {
		wire, active := runError(err)
		h.audit("ipc.run_start", s, active, wire)
		return nil, wire
	}
	h.audit("ipc.run_start", s, runID, nil)
	return StartResult{RunID: runID}, nil
}

func (h *Host) runCancel(ctx context.Context, s *Session, params json.RawMessage) (any, error) {
	var p CancelParams
	if len(params) == 0 || json.Unmarshal(params, &p) != nil || p.RunID == "" {
		return nil, &Error{Code: CodeInvalidParams, Message: "run_id is required"}
	}
	if err := h.o.Runs.Cancel(ctx, p.RunID, s.Peer()); err != nil {
		wire, _ := runError(err)
		h.audit("ipc.run_cancel", s, p.RunID, wire)
		return nil, wire
	}
	h.audit("ipc.run_cancel", s, p.RunID, nil)
	return CancelResult{Accepted: true}, nil
}

// eventsSubscribe answers with the snapshot header and starts the session's
// pump only after that response is written, so the client always sees the
// response, then the replay, then snapshot.done, then live items. A second
// subscribe on the same session replaces the first.
func (h *Host) eventsSubscribe(_ context.Context, s *Session, _ json.RawMessage) (any, error) {
	h.mu.Lock()
	old := h.subs[s]
	delete(h.subs, s)
	h.mu.Unlock()
	if old != nil {
		old.halt()
		<-old.done
	}

	snap, sub := h.o.Hub.Subscribe()
	p := &pump{sub: sub, stop: make(chan struct{}), done: make(chan struct{})}
	s.onReply = func(ok bool) {
		if !ok {
			sub.Close()
			close(p.done)
			return
		}
		h.mu.Lock()
		h.subs[s] = p
		h.mu.Unlock()
		go h.run(s, snap, p)
	}
	return SubscribeResult{Run: runRef(snap.Run), LastSeq: snap.LastSeq}, nil
}

// run is the pump goroutine of one subscription.
func (h *Host) run(s *Session, snap runstate.Snapshot, p *pump) {
	defer func() {
		p.sub.Close()
		h.mu.Lock()
		if h.subs[s] == p {
			delete(h.subs, s)
		}
		h.mu.Unlock()
		close(p.done)
	}()

	for _, it := range snap.Items {
		if h.stopped(s, p) || !h.send(s, it) {
			return
		}
	}
	done := SnapshotDoneParams{LastSeq: snap.LastSeq}
	if snap.Run != nil {
		id := snap.Run.RunID
		done.RunID = &id
	}
	if s.Notify(NotifySnapshotDone, done) != nil {
		return
	}

	for {
		// A dropped subscription is acted on before any item still buffered,
		// so a lagging client is told at once instead of after a stale tail.
		select {
		case <-p.sub.Lagged():
			h.log.Warn("ipc.slow_consumer", s.Peer().LogAttrs()...)
			s.Close(CodeSlowConsumer, "slow consumer")
			return
		default:
		}
		select {
		case <-p.stop:
			return
		case <-s.Done():
			return
		case <-p.sub.Lagged():
			continue
		case it, ok := <-p.sub.C():
			if !ok {
				continue // closed by Close (stop follows) or by a lag drop
			}
			if !h.send(s, it) {
				return
			}
		}
	}
}

func (h *Host) stopped(s *Session, p *pump) bool {
	select {
	case <-p.stop:
		return true
	case <-s.Done():
		return true
	default:
		return false
	}
}

// send writes one item. It returns false when the session is gone. An item
// too large for one line is dropped for this subscriber only.
func (h *Host) send(s *Session, it runstate.Item) bool {
	var err error
	switch it.Kind {
	case runstate.ItemEvent:
		err = s.Notify(NotifyProgress, ProgressParams{RunID: it.RunID, Replay: it.Replay, Event: it.Event})
	case runstate.ItemRunState:
		rs := RunStateParams{RunID: it.RunID, State: it.State, Trigger: it.Trigger, StartedAt: rfc3339(it.StartedAt)}
		if it.State == "ended" {
			rs.Outcome = it.Outcome
		}
		err = s.Notify(NotifyRunState, rs)
	default:
		return true
	}
	if errors.Is(err, ErrLineTooLong) {
		h.log.Warn("ipc.event_dropped_oversize", "run_id", it.RunID, "seq", it.Event.Seq, "kind", string(it.Event.Kind))
		return true
	}
	return err == nil
}
