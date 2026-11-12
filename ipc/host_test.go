// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/ipc/runstate"
	"github.com/59k-ai/cysec-scanner/progress"
)

// fakeRuns is a RunController whose answers are set by the test.
type fakeRuns struct {
	mu        sync.Mutex
	status    RunStatus
	startID   string
	startErr  error
	cancelErr error
	gotParams json.RawMessage
	gotPeer   Peer
	gotCancel string
}

func (f *fakeRuns) Start(_ context.Context, params json.RawMessage, peer Peer) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotParams = append(json.RawMessage(nil), params...)
	f.gotPeer = peer
	if f.startErr != nil {
		return "", f.startErr
	}
	return f.startID, nil
}

func (f *fakeRuns) Cancel(_ context.Context, runID string, peer Peer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotCancel = runID
	f.gotPeer = peer
	return f.cancelErr
}

func (f *fakeRuns) Status() RunStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeRuns) set(fn func(*fakeRuns)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type hostHarness struct {
	host *Host
	hub  *runstate.Hub
	runs *fakeRuns
	l    *pipeListener
	logs *syncBuffer

	extMu sync.Mutex
	ext   any
}

func newHostHarness(t *testing.T, hubOpts runstate.HubOptions, mutate func(*ServerOptions)) *hostHarness {
	t.Helper()
	h := &hostHarness{
		hub:  runstate.NewHub(hubOpts),
		runs: &fakeRuns{status: RunStatus{State: "idle"}, startID: "r1"},
		l:    newPipeListener(),
		logs: &syncBuffer{},
	}
	logger := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	so := ServerOptions{
		Token:      func() string { return goodToken },
		Identify:   func(net.Conn) (Peer, error) { return Peer{UID: 501, GID: 20, PID: 4242}, nil },
		Authorizer: AuthorizerFunc(func(Peer) error { return nil }),
		Name:       "test-host",
		Version:    "0.0.1",
		Logger:     logger,
	}
	if mutate != nil {
		mutate(&so)
	}
	srv, err := NewServer(so)
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewHost(HostOptions{
		Server: srv,
		Hub:    h.hub,
		Runs:   h.runs,
		StatusExt: func() any {
			h.extMu.Lock()
			defer h.extMu.Unlock()
			return h.ext
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.host = host
	go func() { _ = host.Serve(h.l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Shutdown(ctx)
	})
	return h
}

func (h *hostHarness) setExt(v any) {
	h.extMu.Lock()
	defer h.extMu.Unlock()
	h.ext = v
}

// client dials the in-memory listener and authenticates.
func (h *hostHarness) client(t *testing.T) (*Client, HelloResult) {
	t.Helper()
	c := NewClient(h.l.Dial(t))
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := c.Hello(ctx, goodToken, Endpoint{Name: "test", Version: "0"})
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	return c, res
}

func call(t *testing.T, c *Client, method string, params, out any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return c.Call(ctx, method, params, out)
}

func wantCode(t *testing.T, err error, code int, msg string) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error %d, got %v", code, err)
	}
	if e.Code != code {
		t.Fatalf("want code %d, got %d (%s)", code, e.Code, e.Message)
	}
	if msg != "" && e.Message != msg {
		t.Fatalf("want message %q, got %q", msg, e.Message)
	}
	return e
}

func compactJSON(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		t.Fatalf("compact %q: %v", b, err)
	}
	return buf.String()
}

func strp(s string) *string { return &s }

func TestHostStatus(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	c, _ := h.client(t)

	var raw json.RawMessage
	if err := call(t, c, MethodStatusGet, struct{}{}, &raw); err != nil {
		t.Fatal(err)
	}
	if got, want := compactJSON(t, raw), `{"state":"idle","run":null,"next_run_at":null,"ext":{}}`; got != want {
		t.Fatalf("idle status:\n got %s\nwant %s", got, want)
	}

	h.setExt(map[string]int{"k": 1})
	if err := call(t, c, MethodStatusGet, nil, &raw); err != nil {
		t.Fatal(err)
	}
	if got, want := compactJSON(t, raw), `{"state":"idle","run":null,"next_run_at":null,"ext":{"k":1}}`; got != want {
		t.Fatalf("status with ext:\n got %s\nwant %s", got, want)
	}

	vienna := time.FixedZone("plus2", 2*3600)
	next := time.Date(2026, 1, 2, 6, 0, 0, 0, vienna)
	h.runs.set(func(f *fakeRuns) {
		f.status = RunStatus{
			State:     "running",
			Run:       &runstate.RunInfo{RunID: "r1", Trigger: "manual", StartedAt: time.Date(2026, 1, 2, 5, 4, 5, 0, vienna)},
			NextRunAt: &next,
		}
	})
	h.setExt(nil)
	if err := call(t, c, MethodStatusGet, nil, &raw); err != nil {
		t.Fatal(err)
	}
	want := `{"state":"running","run":{"run_id":"r1","trigger":"manual","started_at":"2026-01-02T03:04:05Z"},` +
		`"next_run_at":"2026-01-02T04:00:00Z","ext":{}}`
	if got := compactJSON(t, raw); got != want {
		t.Fatalf("running status:\n got %s\nwant %s", got, want)
	}
}

func TestHostStartWhileRunning(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	c, _ := h.client(t)
	for name, err := range map[string]error{
		"value":   ErrRunInProgress{RunID: "r1"},
		"pointer": &ErrRunInProgress{RunID: "r1"},
		"wrapped": errorsJoin(ErrRunInProgress{RunID: "r1"}),
	} {
		h.runs.set(func(f *fakeRuns) { f.startErr = err })
		e := wantCode(t, call(t, c, MethodRunStart, struct{}{}, nil), CodeRunInProgress, "run already in progress")
		data, _ := e.Data.(map[string]any)
		if data["run_id"] != "r1" {
			t.Fatalf("%s: want data run_id r1, got %#v", name, e.Data)
		}
	}
}

func errorsJoin(err error) error { return errors.Join(errors.New("context"), err) }

func TestHostCancelErrors(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	c, _ := h.client(t)

	h.runs.set(func(f *fakeRuns) { f.cancelErr = ErrNotRunning })
	wantCode(t, call(t, c, MethodRunCancel, map[string]string{"run_id": "r1"}, nil), CodeNotRunning, "no run in progress")

	h.runs.set(func(f *fakeRuns) { f.cancelErr = ErrRunMismatch })
	wantCode(t, call(t, c, MethodRunCancel, map[string]string{"run_id": "r1"}, nil), CodeRunMismatch, "run id does not match")

	h.runs.set(func(f *fakeRuns) { f.cancelErr = nil })
	var raw json.RawMessage
	if err := call(t, c, MethodRunCancel, map[string]string{"run_id": "r7"}, &raw); err != nil {
		t.Fatal(err)
	}
	if got := compactJSON(t, raw); got != `{"accepted":true}` {
		t.Fatalf("cancel result %s", got)
	}
	if h.runs.gotCancel != "r7" {
		t.Fatalf("controller got run id %q", h.runs.gotCancel)
	}

	for _, params := range []any{nil, struct{}{}, map[string]any{"run_id": ""}, map[string]any{"run_id": 5}, []int{1}} {
		wantCode(t, call(t, c, MethodRunCancel, params, nil), CodeInvalidParams, "")
	}
}

func TestHostStartParamsPassThrough(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	c, _ := h.client(t)

	params := json.RawMessage(`{"cidrs":["10.0.0.0/30"],"ports":"22","probe_fragile":false,"extra":{"a":[1,2]}}`)
	h.runs.set(func(f *fakeRuns) { f.startID = "r9" })
	var raw json.RawMessage
	if err := call(t, c, MethodRunStart, params, &raw); err != nil {
		t.Fatal(err)
	}
	if got := compactJSON(t, raw); got != `{"run_id":"r9"}` {
		t.Fatalf("start result %s", got)
	}
	if !bytes.Equal(h.runs.gotParams, params) {
		t.Fatalf("params changed on the way:\n got %s\nwant %s", h.runs.gotParams, params)
	}
	if h.runs.gotPeer.UID != 501 || h.runs.gotPeer.PID != 4242 {
		t.Fatalf("controller got peer %+v", h.runs.gotPeer)
	}

	h.runs.set(func(f *fakeRuns) { f.startErr = &Error{Code: CodeInvalidParams, Message: "bad scope"} })
	wantCode(t, call(t, c, MethodRunStart, params, nil), CodeInvalidParams, "bad scope")

	h.runs.set(func(f *fakeRuns) { f.startErr = errors.New("secret detail") })
	wantCode(t, call(t, c, MethodRunStart, params, nil), CodeInternal, "internal error")
	if strings.Contains(h.logs.String(), "secret detail") {
		t.Fatal("controller error text reached the log")
	}
}

// Wire shapes as a client sees them.
type progressNote struct {
	RunID  string         `json:"run_id"`
	Replay bool           `json:"replay"`
	Event  progress.Event `json:"event"`
}

type runStateNote struct {
	RunID     string  `json:"run_id"`
	State     string  `json:"state"`
	Trigger   string  `json:"trigger"`
	StartedAt string  `json:"started_at"`
	Outcome   *string `json:"outcome"`
}

func decodeParams[T any](t *testing.T, m wireMsg, method string) T {
	t.Helper()
	if m.Method != method || len(m.ID) != 0 {
		t.Fatalf("want %s notification, got %+v (params %s)", method, m, m.Params)
	}
	var v T
	if err := json.Unmarshal(m.Params, &v); err != nil {
		t.Fatalf("decode %s: %v", method, err)
	}
	return v
}

func ev(kind progress.Kind, seq int) progress.Event {
	return progress.Event{Kind: kind, Seq: seq, Phase: "scan"}
}

func scanStart(seq int, scope []string, stages ...string) progress.Event {
	e := ev(progress.ScanStart, seq)
	e.Scan = &progress.ScanInfo{Scope: scope, Stages: stages}
	return e
}

func stageProgress(seq int, stage string, done, total int) progress.Event {
	e := ev(progress.StageProgress, seq)
	e.Agent = strp(stage)
	e.Progress = &progress.StageCounts{Done: done, Total: total}
	return e
}

func hostEvent(seq int, ip string) progress.Event {
	e := ev(progress.Host, seq)
	e.Host = &progress.HostSummary{IP: ip, ExternalID: "ip:" + ip, Services: []progress.ServiceSummary{}}
	return e
}

var testStart = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func subscribeRaw(t *testing.T, h *hostHarness) *raw {
	t.Helper()
	r := newRaw(t, h.l.Dial(t))
	r.hello()
	r.send(`{"jsonrpc":"2.0","id":2,"method":"events.subscribe","params":{}}`)
	return r
}

func TestHostSubscribeSnapshotThenLive(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	h.hub.Begin(runstate.RunInfo{RunID: "r1", Trigger: "manual", StartedAt: testStart})
	for _, e := range []progress.Event{
		scanStart(0, []string{"10.0.0.0/30"}, "discovery", "port"),
		stageProgress(1, "discovery", 1, 4),
		hostEvent(2, "10.0.0.2"),
		stageProgress(3, "port", 10, 100),
		hostEvent(4, "10.0.0.1"),
		stageProgress(5, "discovery", 4, 4),
		hostEvent(6, "10.0.0.3"),
	} {
		h.hub.Publish(e)
	}

	r := subscribeRaw(t, h)
	resp := r.recv()
	if string(resp.ID) != "2" || resp.Error != nil {
		t.Fatalf("first line after subscribe must be its response, got %+v", resp)
	}
	want := `{"run":{"run_id":"r1","trigger":"manual","started_at":"2026-01-02T03:04:05Z"},"last_seq":6}`
	if got := compactJSON(t, resp.Result); got != want {
		t.Fatalf("subscribe result:\n got %s\nwant %s", got, want)
	}

	wantKinds := []progress.Kind{progress.ScanStart, progress.StageProgress, progress.StageProgress, progress.Host, progress.Host, progress.Host}
	wantSeqs := []int{0, 5, 3, 4, 2, 6}
	for i, k := range wantKinds {
		p := decodeParams[progressNote](t, r.recv(), NotifyProgress)
		if !p.Replay || p.RunID != "r1" || p.Event.Kind != k || p.Event.Seq != wantSeqs[i] {
			t.Fatalf("replay %d: want %s seq %d replay, got %+v", i, k, wantSeqs[i], p)
		}
	}
	done := r.recv()
	if done.Method != NotifySnapshotDone {
		t.Fatalf("want snapshot.done after the replay, got %+v", done)
	}
	if got := compactJSON(t, done.Params); got != `{"run_id":"r1","last_seq":6}` {
		t.Fatalf("snapshot.done %s", got)
	}

	h.hub.Publish(hostEvent(7, "10.0.0.4"))
	p := decodeParams[progressNote](t, r.recv(), NotifyProgress)
	if p.Replay || p.Event.Seq != 7 || p.Event.Host == nil || p.Event.Host.IP != "10.0.0.4" {
		t.Fatalf("live event: %+v", p)
	}

	h.hub.SetState("stopping")
	s := decodeParams[runStateNote](t, r.recv(), NotifyRunState)
	if s.State != "stopping" || s.RunID != "r1" || s.Outcome != nil || s.Trigger != "manual" || s.StartedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("stopping: %+v", s)
	}
	h.hub.End("cancelled")
	s = decodeParams[runStateNote](t, r.recv(), NotifyRunState)
	if s.State != "ended" || s.Outcome == nil || *s.Outcome != "cancelled" {
		t.Fatalf("ended: %+v", s)
	}
	h.hub.Begin(runstate.RunInfo{RunID: "r2", Trigger: "schedule", StartedAt: testStart.Add(time.Hour)})
	s = decodeParams[runStateNote](t, r.recv(), NotifyRunState)
	if s.State != "started" || s.RunID != "r2" || s.Trigger != "schedule" || s.StartedAt != "2026-01-02T04:04:05Z" || s.Outcome != nil {
		t.Fatalf("started: %+v", s)
	}
}

func TestHostSubscribeIdle(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	r := subscribeRaw(t, h)
	resp := r.recv()
	if string(resp.ID) != "2" {
		t.Fatalf("want response first, got %+v", resp)
	}
	if got := compactJSON(t, resp.Result); got != `{"run":null,"last_seq":-1}` {
		t.Fatalf("idle subscribe result %s", got)
	}
	done := r.recv()
	if done.Method != NotifySnapshotDone {
		t.Fatalf("want snapshot.done, got %+v", done)
	}
	if got := compactJSON(t, done.Params); got != `{"run_id":null,"last_seq":-1}` {
		t.Fatalf("snapshot.done %s", got)
	}
}

func TestHostSubscribeReplaces(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	r := subscribeRaw(t, h)
	r.recv() // response
	r.recv() // snapshot.done
	r.send(`{"jsonrpc":"2.0","id":3,"method":"events.subscribe","params":{}}`)
	if m := r.recv(); string(m.ID) != "3" {
		t.Fatalf("want second response, got %+v", m)
	}
	if m := r.recv(); m.Method != NotifySnapshotDone {
		t.Fatalf("want snapshot.done, got %+v", m)
	}
	h.hub.Begin(runstate.RunInfo{RunID: "r1", Trigger: "manual", StartedAt: testStart})
	if s := decodeParams[runStateNote](t, r.recv(), NotifyRunState); s.State != "started" {
		t.Fatalf("started: %+v", s)
	}
	// Exactly one copy: the replaced subscription no longer feeds the session.
	h.hub.Publish(hostEvent(0, "10.0.0.1"))
	if p := decodeParams[progressNote](t, r.recv(), NotifyProgress); p.Event.Seq != 0 {
		t.Fatalf("live: %+v", p)
	}
	h.hub.End("completed")
	if s := decodeParams[runStateNote](t, r.recv(), NotifyRunState); s.State != "ended" {
		t.Fatalf("want ended right after the single event copy, got %+v", s)
	}
}

func TestHostSlowConsumer(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{QueueSize: 8}, nil)
	r := subscribeRaw(t, h)
	r.recv() // response
	r.recv() // snapshot.done

	// The client stops reading. Publishing must not wait for it.
	start := time.Now()
	h.hub.Begin(runstate.RunInfo{RunID: "r1", Trigger: "manual", StartedAt: testStart})
	for i := 0; i < 1000; i++ {
		h.hub.Publish(hostEvent(i, "10.0.0.1"))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("publishing 1000 events took %v with a stalled subscriber", d)
	}

	// Once the client reads again it sees at most what was in flight, then
	// the slow-consumer notice, then the end of the connection.
	sawClosing := false
	for !sawClosing {
		m := r.recv()
		if m.Method == NotifySessionClosing {
			var cp ClosingParams
			_ = json.Unmarshal(m.Params, &cp)
			if cp.Code != CodeSlowConsumer {
				t.Fatalf("want closing code %d, got %+v", CodeSlowConsumer, cp)
			}
			sawClosing = true
		}
	}
	r.expectEOF()
	if !strings.Contains(h.logs.String(), `"msg":"ipc.slow_consumer"`) {
		t.Fatalf("no slow-consumer log line:\n%s", h.logs.String())
	}
}

func TestHostOversizeEvent(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	h.hub.Begin(runstate.RunInfo{RunID: "r1", Trigger: "manual", StartedAt: testStart})
	r := subscribeRaw(t, h)
	r.recv() // response
	if m := r.recv(); m.Method != NotifySnapshotDone {
		t.Fatalf("want snapshot.done, got %+v", m)
	}

	big := hostEvent(0, "10.0.0.1")
	big.Host.Hostname = strings.Repeat("h", MaxServerLine)
	h.hub.Publish(big)
	h.hub.Publish(hostEvent(1, "10.0.0.2"))

	p := decodeParams[progressNote](t, r.recv(), NotifyProgress)
	if p.Event.Seq != 1 {
		t.Fatalf("want the event after the oversize one, got seq %d", p.Event.Seq)
	}
	if !strings.Contains(h.logs.String(), `"msg":"ipc.event_dropped_oversize"`) {
		t.Fatalf("no oversize log line:\n%s", h.logs.String())
	}
	// The session is still usable.
	r.send(`{"jsonrpc":"2.0","id":9,"method":"status.get","params":{}}`)
	if m := r.recv(); string(m.ID) != "9" || m.Error != nil {
		t.Fatalf("session broken after an oversize event: %+v", m)
	}
}

func TestHostExtension(t *testing.T) {
	hub := runstate.NewHub(runstate.HubOptions{})
	srv, err := NewServer(ServerOptions{
		Token:      func() string { return goodToken },
		Identify:   func(net.Conn) (Peer, error) { return Peer{UID: 501}, nil },
		Authorizer: AuthorizerFunc(func(Peer) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]HostOptions{
		"server": {Hub: hub, Runs: &fakeRuns{}},
		"hub":    {Server: srv, Runs: &fakeRuns{}},
		"runs":   {Server: srv, Hub: hub},
	} {
		if _, err := NewHost(o); err == nil {
			t.Fatalf("NewHost accepted a missing %s", name)
		}
	}

	h := newHostHarness(t, runstate.HubOptions{}, nil)
	h.host.Handle("last_run.get", func(context.Context, *Session, json.RawMessage) (any, error) {
		return map[string]any{"summary": nil}, nil
	})
	for _, m := range []string{MethodStatusGet, MethodRunStart, MethodRunCancel, MethodEventsSubscribe} {
		func() {
			defer func() {
				r := recover()
				if r == nil || !strings.Contains(fmtAny(r), "standard") {
					t.Fatalf("Handle(%q) did not refuse with a clear message: %v", m, r)
				}
			}()
			h.host.Handle(m, func(context.Context, *Session, json.RawMessage) (any, error) { return nil, nil })
		}()
	}

	c, hello := h.client(t)
	got := strings.Join(hello.Methods, ",")
	for _, m := range []string{"events.subscribe", "last_run.get", "run.cancel", "run.start", "status.get"} {
		if !strings.Contains(got, m) {
			t.Fatalf("hello methods %v miss %s", hello.Methods, m)
		}
	}
	var raw json.RawMessage
	if err := call(t, c, "last_run.get", nil, &raw); err != nil {
		t.Fatal(err)
	}
	if compactJSON(t, raw) != `{"summary":null}` {
		t.Fatalf("extension result %s", raw)
	}
	// The standard handler is still the one that answers.
	if err := call(t, c, MethodStatusGet, nil, &raw); err != nil || !strings.Contains(string(raw), `"state":"idle"`) {
		t.Fatalf("status.get after refused override: %s %v", raw, err)
	}
}

func fmtAny(v any) string {
	if e, ok := v.(error); ok {
		return e.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestHostAuditLog(t *testing.T) {
	h := newHostHarness(t, runstate.HubOptions{}, nil)
	c, _ := h.client(t)
	if err := call(t, c, MethodRunStart, struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := call(t, c, MethodRunCancel, map[string]string{"run_id": "r1"}, nil); err != nil {
		t.Fatal(err)
	}
	h.runs.set(func(f *fakeRuns) { f.startErr = ErrRunInProgress{RunID: "r1"} })
	_ = call(t, c, MethodRunStart, struct{}{}, nil)

	type line struct {
		Msg   string  `json:"msg"`
		UID   *int    `json:"uid"`
		PID   *int    `json:"pid"`
		SID   *string `json:"sid"`
		RunID string  `json:"run_id"`
		Code  int     `json:"code"`
	}
	var starts, cancels []line
	for _, l := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		var v line
		if json.Unmarshal([]byte(l), &v) != nil {
			continue
		}
		switch v.Msg {
		case "ipc.run_start":
			starts = append(starts, v)
		case "ipc.run_cancel":
			cancels = append(cancels, v)
		}
	}
	if len(starts) != 2 || len(cancels) != 1 {
		t.Fatalf("want 2 run_start and 1 run_cancel lines, got %d/%d:\n%s", len(starts), len(cancels), h.logs.String())
	}
	for _, v := range append(starts, cancels...) {
		if v.UID == nil || *v.UID != 501 || v.PID == nil || *v.PID != 4242 || v.SID == nil {
			t.Fatalf("audit line without peer identity: %+v", v)
		}
		if v.RunID != "r1" {
			t.Fatalf("audit line without run id: %+v", v)
		}
	}
	if starts[0].Code != 0 || starts[1].Code != CodeRunInProgress {
		t.Fatalf("audit result codes: %+v", starts)
	}
}
