// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/ipc/runstate"
	"github.com/59k-ai/cysec-scanner/progress"
)

// e2eEndpoint returns a listen address and options for a real local endpoint
// that only the current user can reach.
func e2eEndpoint(t *testing.T) ListenOptions {
	t.Helper()
	if runtime.GOOS == "windows" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		sid, err := CurrentUserSID()
		if err != nil {
			t.Fatal(err)
		}
		return ListenOptions{
			Address: `\\.\pipe\scanner-ipc-test-` + hex.EncodeToString(b[:]),
			Pipe:    PipeOptions{SDDL: SameUserPipeSDDL(sid)},
		}
	}
	// The per-test temp dir on macOS is too deep for the sun_path limit.
	d, err := os.MkdirTemp("/tmp", "ipch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return ListenOptions{Address: filepath.Join(d, "s.sock"), Unix: UnixOptions{
		DirOwnerUID: os.Geteuid(), DirGID: -1, SocketGID: -1, SocketMode: 0o600,
	}}
}

// scriptRuns is a RunController that publishes a long scripted run until it
// finishes or is cancelled.
type scriptRuns struct {
	hub  *runstate.Hub
	step time.Duration
	n    int

	mu     sync.Mutex
	runID  string
	cancel chan struct{}
	seq    int
	wg     sync.WaitGroup
}

func (s *scriptRuns) Start(_ context.Context, _ json.RawMessage, _ Peer) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runID != "" {
		return "", ErrRunInProgress{RunID: s.runID}
	}
	s.seq++
	s.runID = fmt.Sprintf("run-%d", s.seq)
	s.cancel = make(chan struct{})
	s.hub.Begin(runstate.RunInfo{RunID: s.runID, Trigger: "manual", StartedAt: time.Now()})
	s.wg.Add(1)
	go s.play(s.cancel)
	return s.runID, nil
}

func (s *scriptRuns) play(cancel <-chan struct{}) {
	defer s.wg.Done()
	s.hub.Publish(scanStart(0, []string{"10.0.0.0/24"}, "discovery"))
	status := "completed"
	seq := 1
	for i := 0; i < s.n; i++ {
		select {
		case <-cancel:
			status = "cancelled"
		case <-time.After(s.step):
			s.hub.Publish(hostEvent(seq, fmt.Sprintf("10.0.0.%d", i%250+1)))
			seq++
			continue
		}
		break
	}
	end := ev(progress.ScanEnd, seq)
	end.ScanEnd = &progress.ScanEndInfo{Status: status}
	s.hub.Publish(end)
	s.mu.Lock()
	s.runID = ""
	s.mu.Unlock()
	s.hub.End(status)
}

func (s *scriptRuns) Cancel(_ context.Context, runID string, _ Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.runID == "":
		return ErrNotRunning
	case runID != s.runID:
		return ErrRunMismatch
	}
	select {
	case <-s.cancel:
	default:
		close(s.cancel)
		s.hub.SetState("stopping")
	}
	return nil
}

func (s *scriptRuns) Status() RunStatus {
	return RunStatus{State: s.hub.Status(), Run: s.hub.Run()}
}

func e2eClient(t *testing.T, addr, token string) (*Client, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := Dial(ctx, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := NewClient(conn)
	t.Cleanup(func() { c.Close() })
	_, err = c.Hello(ctx, token, Endpoint{Name: "e2e", Version: "0"})
	return c, err
}

func nextNote(t *testing.T, c *Client) Notification {
	t.Helper()
	select {
	case n, ok := <-c.Notifications():
		if !ok {
			t.Fatal("notification stream closed")
		}
		return n
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a notification")
	}
	return Notification{}
}

func noteParams[T any](t *testing.T, n Notification) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(n.Params.(json.RawMessage), &v); err != nil {
		t.Fatalf("decode %s: %v", n.Method, err)
	}
	return v
}

func TestHostEndToEnd(t *testing.T) {
	lo := e2eEndpoint(t)
	l, err := Listen(lo)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	token, err := NewToken("")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerOptions{
		Token:      func() string { return token },
		Identify:   l.Identify(),
		Authorizer: SameUserAuthorizer(),
		Name:       "e2e-host",
		Version:    "0",
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := runstate.NewHub(runstate.HubOptions{})
	runs := &scriptRuns{hub: hub, step: 10 * time.Millisecond, n: 2000}
	host, err := NewHost(HostOptions{Server: srv, Hub: hub, Runs: runs})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- host.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Shutdown(ctx)
		runs.wg.Wait()
	})

	// A wrong token is refused.
	if _, err := e2eClient(t, lo.Address, token+"x"); err == nil {
		t.Fatal("wrong token accepted")
	} else {
		wantCode(t, err, CodeUnauthenticated, "")
	}

	a, err := e2eClient(t, lo.Address, token)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	var st StatusResult
	if err := call(t, a, MethodStatusGet, nil, &st); err != nil || st.State != "idle" || st.Run != nil {
		t.Fatalf("idle status %+v %v", st, err)
	}
	var sub SubscribeResult
	if err := call(t, a, MethodEventsSubscribe, nil, &sub); err != nil || sub.Run != nil || sub.LastSeq != -1 {
		t.Fatalf("idle subscribe %+v %v", sub, err)
	}
	if n := nextNote(t, a); n.Method != NotifySnapshotDone {
		t.Fatalf("want snapshot.done, got %s", n.Method)
	}

	var started StartResult
	if err := call(t, a, MethodRunStart, nil, &started); err != nil || started.RunID == "" {
		t.Fatalf("run.start %+v %v", started, err)
	}
	if err := call(t, a, MethodRunStart, nil, nil); err == nil {
		t.Fatal("second run.start accepted")
	} else {
		wantCode(t, err, CodeRunInProgress, "run already in progress")
	}
	if s := noteParams[RunStateParams](t, nextNote(t, a)); s.State != "started" || s.RunID != started.RunID {
		t.Fatalf("started: %+v", s)
	}
	live := 0
	for live < 5 {
		n := nextNote(t, a)
		if n.Method != NotifyProgress {
			t.Fatalf("want live progress, got %s", n.Method)
		}
		if p := noteParams[progressNote](t, n); p.Replay || p.RunID != started.RunID {
			t.Fatalf("live progress %+v", p)
		}
		live++
	}

	// A second client attaching mid-run gets the snapshot first.
	b, err := e2eClient(t, lo.Address, token)
	if err != nil {
		t.Fatalf("second hello: %v", err)
	}
	var sub2 SubscribeResult
	if err := call(t, b, MethodEventsSubscribe, nil, &sub2); err != nil || sub2.Run == nil || sub2.Run.RunID != started.RunID || sub2.LastSeq < 1 {
		t.Fatalf("mid-run subscribe %+v %v", sub2, err)
	}
	if p := noteParams[progressNote](t, nextNote(t, b)); !p.Replay || p.Event.Kind != progress.ScanStart {
		t.Fatalf("first replay item %+v", p)
	}
	for {
		n := nextNote(t, b)
		if n.Method == NotifySnapshotDone {
			d := noteParams[SnapshotDoneParams](t, n)
			if d.RunID == nil || *d.RunID != started.RunID || d.LastSeq != sub2.LastSeq {
				t.Fatalf("snapshot.done %+v", d)
			}
			break
		}
		if p := noteParams[progressNote](t, n); !p.Replay {
			t.Fatalf("live item before snapshot.done: %+v", p)
		}
	}
	n := nextNote(t, b)
	if p := noteParams[progressNote](t, n); n.Method != NotifyProgress || p.Replay || p.Event.Seq != sub2.LastSeq+1 {
		t.Fatalf("first live item after snapshot.done: %s %+v (last_seq %d)", n.Method, p, sub2.LastSeq)
	}

	if err := call(t, a, MethodRunCancel, CancelParams{RunID: "other"}, nil); err == nil {
		t.Fatal("cancel with the wrong run id accepted")
	} else {
		wantCode(t, err, CodeRunMismatch, "")
	}
	var cr CancelResult
	if err := call(t, a, MethodRunCancel, CancelParams{RunID: started.RunID}, &cr); err != nil || !cr.Accepted {
		t.Fatalf("run.cancel %+v %v", cr, err)
	}
	sawStopping, sawEnd := false, false
	for !sawEnd {
		n := nextNote(t, a)
		switch n.Method {
		case NotifyRunState:
			s := noteParams[RunStateParams](t, n)
			switch s.State {
			case "stopping":
				sawStopping = true
			case "ended":
				if s.Outcome != "cancelled" {
					t.Fatalf("ended outcome %q", s.Outcome)
				}
				sawEnd = true
			}
		case NotifyProgress:
		default:
			t.Fatalf("unexpected %s", n.Method)
		}
	}
	if !sawStopping {
		t.Fatal("no stopping state before ended")
	}
	if err := call(t, a, MethodRunCancel, CancelParams{RunID: started.RunID}, nil); err == nil {
		t.Fatal("cancel after the end accepted")
	} else {
		wantCode(t, err, CodeNotRunning, "")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := host.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve returned %v", err)
	}
}
