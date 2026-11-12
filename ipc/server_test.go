// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const goodToken = "tok_" + "GOODgoodGOODgoodGOODgoodGOODgoodGOODgoodGOO"

// pipeListener is an in-memory net.Listener built from net.Pipe pairs, so the
// server is exercised without any operating-system socket.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (l *pipeListener) Dial(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	select {
	case l.conns <- server:
	case <-l.closed:
		t.Fatal("listener closed")
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept")
	}
	t.Cleanup(func() { client.Close() })
	return client
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// syncBuffer is a goroutine-safe bytes.Buffer for log capture.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	srv        *Server
	l          *pipeListener
	tokenCalls atomic.Int32
	statusRuns atomic.Int32
	logs       *syncBuffer
	serveErr   chan error
}

func newHarness(t *testing.T, mutate func(*ServerOptions)) *harness {
	t.Helper()
	h := &harness{l: newPipeListener(), logs: &syncBuffer{}, serveErr: make(chan error, 1)}
	o := ServerOptions{
		Token: func() string {
			h.tokenCalls.Add(1)
			return goodToken
		},
		Identify:   func(net.Conn) (Peer, error) { return Peer{UID: 501, GID: 20, PID: 4242}, nil },
		Authorizer: AuthorizerFunc(func(Peer) error { return nil }),
		Name:       "refhost",
		Version:    "1.2.3",
		Logger:     slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if mutate != nil {
		mutate(&o)
	}
	srv, err := NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	srv.Handle(MethodStatusGet, func(context.Context, *Session, json.RawMessage) (any, error) {
		h.statusRuns.Add(1)
		return map[string]string{"state": "idle"}, nil
	})
	go func() { h.serveErr <- srv.Serve(h.l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return h
}

// raw drives a connection line by line and records every byte received.
type raw struct {
	t    *testing.T
	conn net.Conn
	lr   *LineReader
	seen bytes.Buffer
}

func newRaw(t *testing.T, c net.Conn) *raw {
	return &raw{t: t, conn: c, lr: NewLineReader(c)}
}

func (r *raw) send(line string) {
	r.t.Helper()
	_ = r.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(r.conn, line+"\n"); err != nil {
		r.t.Fatalf("send: %v", err)
	}
}

type wireMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func (r *raw) recv() wireMsg {
	r.t.Helper()
	_ = r.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := r.lr.ReadLine(1 << 20)
	if err != nil {
		r.t.Fatalf("recv: %v", err)
	}
	r.seen.Write(line)
	r.seen.WriteByte('\n')
	var m wireMsg
	if err := json.Unmarshal(line, &m); err != nil {
		r.t.Fatalf("recv decode %q: %v", line, err)
	}
	if m.JSONRPC != "2.0" {
		r.t.Fatalf("missing jsonrpc 2.0: %q", line)
	}
	return m
}

func (r *raw) expectError(code int, id string) wireMsg {
	r.t.Helper()
	m := r.recv()
	if m.Error == nil || m.Error.Code != code {
		r.t.Fatalf("want error %d, got %+v", code, m)
	}
	if string(m.ID) != id {
		r.t.Fatalf("want id %s, got %s", id, m.ID)
	}
	if m.Result != nil {
		r.t.Fatalf("error response carries a result: %s", m.Result)
	}
	return m
}

func (r *raw) expectEOF() {
	r.t.Helper()
	_ = r.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		line, err := r.lr.ReadLine(1 << 20)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			r.t.Fatalf("want EOF, got %v", err)
		}
		r.t.Fatalf("want EOF, got line %q", line)
	}
}

func helloLine(id int, protocol int, token string) string {
	b, _ := json.Marshal(Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(strings.TrimSpace(string(mustJSON(id)))),
		Method:  MethodHello,
		Params:  mustJSON(HelloParams{Protocol: protocol, Token: token, Client: Endpoint{Name: "test", Version: "0"}}),
	})
	return string(b)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (r *raw) hello() {
	r.t.Helper()
	r.send(helloLine(1, ProtocolVersion, goodToken))
	m := r.recv()
	if m.Error != nil {
		r.t.Fatalf("hello refused: %+v", m.Error)
	}
}

func TestNewServerRefusesMissingAuthHooks(t *testing.T) {
	ok := ServerOptions{
		Token:      func() string { return goodToken },
		Identify:   func(net.Conn) (Peer, error) { return Peer{}, nil },
		Authorizer: AuthorizerFunc(func(Peer) error { return nil }),
	}
	for name, mutate := range map[string]func(*ServerOptions){
		"token":      func(o *ServerOptions) { o.Token = nil },
		"identify":   func(o *ServerOptions) { o.Identify = nil },
		"authorizer": func(o *ServerOptions) { o.Authorizer = nil },
	} {
		o := ok
		mutate(&o)
		if _, err := NewServer(o); err == nil {
			t.Fatalf("NewServer accepted a nil %s hook", name)
		}
	}
	if _, err := NewServer(ok); err != nil {
		t.Fatal(err)
	}
}

func TestHelloRequiredFirst(t *testing.T) {
	h := newHarness(t, nil)
	r := newRaw(t, h.l.Dial(t))
	r.send(`{"jsonrpc":"2.0","id":1,"method":"status.get","params":{}}`)
	m := r.expectError(CodeUnauthenticated, "1")
	if m.Error.Message != "unauthenticated" {
		t.Fatalf("message %q", m.Error.Message)
	}
	r.expectEOF()
	if n := h.statusRuns.Load(); n != 0 {
		t.Fatalf("status.get ran %d times before hello", n)
	}
}

func TestHelloWrongToken(t *testing.T) {
	h := newHarness(t, nil)
	h.srv.Handle("run.start", func(context.Context, *Session, json.RawMessage) (any, error) { return nil, nil })
	h.srv.Handle("alpha.thing", func(context.Context, *Session, json.RawMessage) (any, error) { return nil, nil })

	r := newRaw(t, h.l.Dial(t))
	r.send(helloLine(1, ProtocolVersion, "tok_wrong"))
	r.expectError(CodeUnauthenticated, "1")
	r.expectEOF()

	c := NewClient(h.l.Dial(t))
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := c.Hello(ctx, goodToken, Endpoint{Name: "test", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != 1 || res.Server != (Endpoint{Name: "refhost", Version: "1.2.3"}) {
		t.Fatalf("hello result %+v", res)
	}
	want := []string{"alpha.thing", "run.start", "status.get"}
	if !reflect.DeepEqual(res.Methods, want) {
		t.Fatalf("methods %v, want %v", res.Methods, want)
	}
	var st map[string]string
	if err := c.Call(ctx, MethodStatusGet, map[string]any{}, &st); err != nil || st["state"] != "idle" {
		t.Fatalf("status.get after hello: %v %v", st, err)
	}

	c2 := NewClient(h.l.Dial(t))
	defer c2.Close()
	_, err = c2.Hello(ctx, "tok_wrong", Endpoint{Name: "test"})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeUnauthenticated {
		t.Fatalf("client hello with wrong token: %v", err)
	}
}

func TestHelloPeerRefused(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) {
		o.Authorizer = AuthorizerFunc(func(Peer) error { return errors.New("not an admin") })
	})
	r := newRaw(t, h.l.Dial(t))
	r.send(helloLine(5, ProtocolVersion, goodToken))
	r.expectError(CodeUnauthenticated, "5")
	r.expectEOF()

	h2 := newHarness(t, func(o *ServerOptions) {
		o.Identify = func(net.Conn) (Peer, error) { return Peer{}, errors.New("no credentials") }
	})
	r2 := newRaw(t, h2.l.Dial(t))
	r2.send(helloLine(6, ProtocolVersion, goodToken))
	r2.expectError(CodeUnauthenticated, "6")
	r2.expectEOF()
}

func TestHelloDeadline(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) { o.HelloTimeout = 50 * time.Millisecond })
	start := time.Now()
	r := newRaw(t, h.l.Dial(t))
	r.expectError(CodeUnauthenticated, "null")
	r.expectEOF()
	if el := time.Since(start); el > time.Second {
		t.Fatalf("server took %v to drop a silent client", el)
	}
}

func TestHelloTooLarge(t *testing.T) {
	h := newHarness(t, nil)
	r := newRaw(t, h.l.Dial(t))
	r.send(`{"jsonrpc":"2.0","id":1,"method":"session.hello","params":{"pad":"` + strings.Repeat("x", 5000) + `"}}`)
	r.expectError(CodeUnauthenticated, "null")
	r.expectEOF()
	if n := h.tokenCalls.Load(); n != 0 {
		t.Fatalf("token compared %d times for an oversize hello", n)
	}
}

func TestHelloProtocolMismatch(t *testing.T) {
	h := newHarness(t, nil)
	r := newRaw(t, h.l.Dial(t))
	r.send(helloLine(3, 2, goodToken))
	m := r.expectError(CodeUnsupportedProtocol, "3")
	var data map[string]int
	if err := json.Unmarshal(m.Error.Data, &data); err != nil || data["min"] != 1 || data["max"] != 1 || len(data) != 2 {
		t.Fatalf("data %s", m.Error.Data)
	}
	r.expectEOF()
}

func TestHelloTokenRotation(t *testing.T) {
	var mu sync.Mutex
	current := "tok_first"
	h := newHarness(t, func(o *ServerOptions) {
		o.Token = func() string {
			mu.Lock()
			defer mu.Unlock()
			return current
		}
	})
	a := newRaw(t, h.l.Dial(t))
	a.send(helloLine(1, ProtocolVersion, "tok_first"))
	if m := a.recv(); m.Error != nil {
		t.Fatalf("first token refused: %+v", m.Error)
	}

	mu.Lock()
	current = "tok_second"
	mu.Unlock()

	b := newRaw(t, h.l.Dial(t))
	b.send(helloLine(1, ProtocolVersion, "tok_first"))
	b.expectError(CodeUnauthenticated, "1")
	b.expectEOF()

	c := newRaw(t, h.l.Dial(t))
	c.send(helloLine(1, ProtocolVersion, "tok_second"))
	if m := c.recv(); m.Error != nil {
		t.Fatalf("rotated token refused: %+v", m.Error)
	}
}

func TestMethods(t *testing.T) {
	h := newHarness(t, nil)
	h.srv.Handle("busy", func(context.Context, *Session, json.RawMessage) (any, error) {
		return nil, &Error{Code: CodeRunInProgress, Message: "run already in progress", Data: map[string]string{"run_id": "r1"}}
	})
	h.srv.Handle("boom", func(context.Context, *Session, json.RawMessage) (any, error) {
		return nil, errors.New("secret detail")
	})
	h.srv.Handle("panics", func(context.Context, *Session, json.RawMessage) (any, error) {
		panic("secret detail")
	})
	h.srv.Handle("empty", func(context.Context, *Session, json.RawMessage) (any, error) { return nil, nil })

	r := newRaw(t, h.l.Dial(t))
	r.hello()

	r.send(`{"jsonrpc":"2.0","id":2,"method":"nope"}`)
	r.expectError(CodeMethodNotFound, "2")

	r.send(`not json`)
	r.expectError(CodeParse, "null")

	r.send(`{"jsonrpc":"2.0","id":3}`)
	r.expectError(CodeInvalidRequest, "3")

	r.send(`[1,2]`)
	r.expectError(CodeInvalidRequest, "null")

	r.send(`{"jsonrpc":"2.0","id":4,"method":"busy"}`)
	m := r.expectError(CodeRunInProgress, "4")
	if m.Error.Message != "run already in progress" || string(m.Error.Data) != `{"run_id":"r1"}` {
		t.Fatalf("app error not verbatim: %+v %s", m.Error, m.Error.Data)
	}

	r.send(`{"jsonrpc":"2.0","id":5,"method":"boom"}`)
	m = r.expectError(CodeInternal, "5")
	if m.Error.Message != "internal error" {
		t.Fatalf("internal message %q", m.Error.Message)
	}

	r.send(`{"jsonrpc":"2.0","id":6,"method":"panics"}`)
	r.expectError(CodeInternal, "6")

	r.send(`{"jsonrpc":"2.0","id":7,"method":"empty"}`)
	if m := r.recv(); m.Error != nil || string(m.Result) != "{}" {
		t.Fatalf("nil result must encode as {}: %+v %s", m.Error, m.Result)
	}

	pad := strings.Repeat("x", MaxRequestLine)
	r.send(`{"jsonrpc":"2.0","id":8,"method":"status.get","params":{"pad":"` + pad + `"}}`)
	r.expectError(CodeInvalidRequest, "null")

	// A notification gets no response; the next answer carries the next id.
	r.send(`{"jsonrpc":"2.0","method":"status.get"}`)
	r.send(`{"jsonrpc":"2.0","id":9,"method":"status.get","params":{}}`)
	m = r.recv()
	if m.Error != nil || string(m.ID) != "9" {
		t.Fatalf("session unusable after oversize line: %+v", m)
	}
	if n := h.statusRuns.Load(); n != 1 {
		t.Fatalf("status.get ran %d times, want 1 (notification and oversize ignored)", n)
	}

	if strings.Contains(r.seen.String(), "secret detail") {
		t.Fatal("handler error text reached the wire")
	}
	if strings.Contains(h.logs.String(), "secret detail") {
		t.Fatal("handler error text reached the log")
	}
}

func TestSessionNotify(t *testing.T) {
	h := newHarness(t, nil)
	var gotPeer Peer
	h.srv.Handle("ping", func(ctx context.Context, s *Session, _ json.RawMessage) (any, error) {
		gotPeer = s.Peer()
		if err := s.Notify(NotifyRunState, map[string]string{"state": "started"}); err != nil {
			return nil, err
		}
		if err := s.Notify(NotifyProgress, map[string]string{"pad": strings.Repeat("x", MaxServerLine)}); !errors.Is(err, ErrLineTooLong) {
			t.Errorf("oversize notify: %v", err)
		}
		return map[string]bool{"ok": true}, nil
	})
	c := NewClient(h.l.Dial(t))
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Hello(ctx, goodToken, Endpoint{Name: "test"}); err != nil {
		t.Fatal(err)
	}
	var out map[string]bool
	if err := c.Call(ctx, "ping", nil, &out); err != nil || !out["ok"] {
		t.Fatalf("ping: %v %v", out, err)
	}
	select {
	case n := <-c.Notifications():
		raw, ok := n.Params.(json.RawMessage)
		if n.Method != NotifyRunState || !ok || string(raw) != `{"state":"started"}` {
			t.Fatalf("notification %+v", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no notification")
	}
	if gotPeer.UID != 501 || gotPeer.PID != 4242 {
		t.Fatalf("session peer %+v", gotPeer)
	}
}

func TestSessionCap(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) { o.MaxSessions = 2 })
	a := newRaw(t, h.l.Dial(t))
	a.hello()
	b := newRaw(t, h.l.Dial(t))
	b.hello()

	c := newRaw(t, h.l.Dial(t))
	m := c.recv()
	if m.Method != NotifySessionClosing || len(m.ID) != 0 {
		t.Fatalf("want session.closing, got %+v", m)
	}
	var p ClosingParams
	if err := json.Unmarshal(m.Params, &p); err != nil || p.Code != CodeShuttingDown {
		t.Fatalf("closing params %s", m.Params)
	}
	c.expectEOF()

	// The open sessions are unaffected.
	a.send(`{"jsonrpc":"2.0","id":2,"method":"status.get","params":{}}`)
	if m := a.recv(); m.Error != nil {
		t.Fatalf("existing session broken: %+v", m.Error)
	}
}

func TestShutdown(t *testing.T) {
	h := newHarness(t, nil)
	var sessions []*raw
	for i := 0; i < 3; i++ {
		r := newRaw(t, h.l.Dial(t))
		r.hello()
		sessions = append(sessions, r)
	}

	shut := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shut <- h.srv.Shutdown(ctx)
	}()

	for _, r := range sessions {
		m := r.recv()
		var p ClosingParams
		if m.Method != NotifySessionClosing || json.Unmarshal(m.Params, &p) != nil || p.Code != CodeShuttingDown {
			t.Fatalf("want session.closing -32011, got %+v", m)
		}
		r.expectEOF()
	}
	if err := <-shut; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-h.serveErr:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	if err := h.srv.Serve(newPipeListener()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Shutdown: %v", err)
	}
}

func TestNoTokenInLogs(t *testing.T) {
	h := newHarness(t, nil)
	const wrong = "tok_WRONGwrongWRONGwrongWRONGwrongWRONGwrongWR"

	r := newRaw(t, h.l.Dial(t))
	r.send(helloLine(1, ProtocolVersion, wrong))
	r.expectError(CodeUnauthenticated, "1")
	r.expectEOF()

	r2 := newRaw(t, h.l.Dial(t))
	r2.hello()

	// Shut down so every log line has been written before reading.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		for {
			if _, err := r2.lr.ReadLine(1 << 20); err != nil {
				return
			}
		}
	}()
	if err := h.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	logs := h.logs.String()
	for _, tok := range []string{wrong, goodToken} {
		if strings.Contains(logs, tok) {
			t.Fatalf("token %q found in logs:\n%s", tok, logs)
		}
	}
	for _, id := range []string{"ipc.auth_refused", "ipc.session_open"} {
		if !strings.Contains(logs, id) {
			t.Fatalf("log line %s missing:\n%s", id, logs)
		}
	}
}

func TestReadFailureAuditNeverReadsAsRoot(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) {
		o.Identify = func(net.Conn) (Peer, error) { return Peer{}, errors.New("no identity") }
	})
	c := h.l.Dial(t)
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(h.logs.String(), `"ipc.auth_refused"`) {
		if time.Now().After(deadline) {
			t.Fatalf("no refusal logged: %s", h.logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if logs := h.logs.String(); strings.Contains(logs, `"uid":0`) || !strings.Contains(logs, `"uid":-1`) {
		t.Fatalf("audit line for an unidentified peer: %s", logs)
	}
}

func TestRefusedConnectionsDoNotHoldShutdown(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) {
		o.MaxSessions = 1
		o.WriteTimeout = 30 * time.Second
	})
	a := newRaw(t, h.l.Dial(t))
	a.hello()
	// Over the cap and never reading: the closing notice cannot be written.
	for range 3 {
		_ = h.l.Dial(t)
	}
	time.Sleep(20 * time.Millisecond)
	began := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		// The authenticated session reads its notice, so only refusals could hold
		// the shutdown.
		_ = a.recv()
	}()
	if err := h.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("Shutdown waited %v on refused connections", took)
	}
}

func TestRefusalNoticeHasAShortDeadline(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) {
		o.MaxSessions = 1
		o.WriteTimeout = 30 * time.Second
	})
	a := newRaw(t, h.l.Dial(t))
	a.hello()
	c := h.l.Dial(t)
	// Never read: the notice write must give up after the refusal deadline and
	// drop the connection.
	time.Sleep(refusalWriteTimeout + 500*time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("a refused connection was still open after the refusal deadline: %v", err)
	}
}

func TestIdleTimeout(t *testing.T) {
	h := newHarness(t, func(o *ServerOptions) { o.IdleTimeout = 150 * time.Millisecond })
	r := newRaw(t, h.l.Dial(t))
	r.hello()
	// Requests inside the window keep the session.
	for i := range 3 {
		time.Sleep(80 * time.Millisecond)
		r.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"status.get","params":{}}`, 10+i))
		if m := r.recv(); m.Error != nil {
			t.Fatalf("request %d inside the idle window: %+v", i, m.Error)
		}
	}
	// Silence past it ends the session with a notice.
	m := r.recv()
	var p ClosingParams
	if m.Method != NotifySessionClosing || json.Unmarshal(m.Params, &p) != nil || p.Reason != "idle timeout" {
		t.Fatalf("want an idle session.closing, got %+v", m)
	}
	r.expectEOF()
}

func TestNoIdleTimeoutByDefault(t *testing.T) {
	h := newHarness(t, nil)
	r := newRaw(t, h.l.Dial(t))
	r.hello()
	time.Sleep(200 * time.Millisecond)
	r.send(`{"jsonrpc":"2.0","id":2,"method":"status.get","params":{}}`)
	if m := r.recv(); m.Error != nil {
		t.Fatalf("an idle session was dropped by default: %+v", m.Error)
	}
}

func TestMaxSessionsPerPeer(t *testing.T) {
	var uid atomic.Int32
	uid.Store(501)
	h := newHarness(t, func(o *ServerOptions) {
		o.MaxSessionsPerPeer = 2
		o.Identify = func(net.Conn) (Peer, error) { return Peer{UID: int(uid.Load()), GID: 20, PID: 1}, nil }
	})
	a := newRaw(t, h.l.Dial(t))
	a.hello()
	b := newRaw(t, h.l.Dial(t))
	b.hello()

	c := newRaw(t, h.l.Dial(t))
	c.send(helloLine(1, ProtocolVersion, goodToken))
	if m := c.recv(); m.Method != NotifySessionClosing {
		t.Fatalf("a third session of one peer: %+v", m)
	}
	c.expectEOF()

	// Another principal still gets in.
	uid.Store(502)
	d := newRaw(t, h.l.Dial(t))
	d.hello()

	// A closed session frees its slot.
	uid.Store(501)
	_ = a.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e := newRaw(t, h.l.Dial(t))
		e.send(helloLine(1, ProtocolVersion, goodToken))
		if m := e.recv(); m.Error == nil && m.Method == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a closed session never freed its peer slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
