// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// Server defaults.
const (
	DefaultHelloTimeout = 5 * time.Second
	DefaultMaxSessions  = 8
	DefaultWriteTimeout = 10 * time.Second
)

// refusalWriteTimeout bounds the session.closing notice to a connection over
// the session cap. It is short and fixed: the notice is a courtesy, and a
// connect flood must not hold one goroutine per connection for WriteTimeout.
const refusalWriteTimeout = 250 * time.Millisecond

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("ipc: server closed")

// errSessionClosed is returned by Notify on a session that has ended.
var errSessionClosed = errors.New("ipc: session closed")

// HandlerFunc serves one method. ctx is the session context, cancelled when
// the session ends. Return *Error to send a specific error code; any other
// error is sent as CodeInternal with a fixed message. A nil result is sent as
// an empty object.
type HandlerFunc func(ctx context.Context, s *Session, params json.RawMessage) (any, error)

// ServerOptions configure a Server. Token, Identify and Authorizer are
// required: there is no unauthenticated mode.
type ServerOptions struct {
	// Token returns the current capability token. It is read on every hello,
	// so a host can rotate the token without restarting the server.
	Token func() string
	// Identify reads the kernel-reported identity of the connecting peer.
	Identify IdentifyFunc
	// Authorizer decides whether that peer may open a session.
	Authorizer Authorizer
	// HelloTimeout bounds how long a new connection may take to send its
	// hello line. Default DefaultHelloTimeout.
	HelloTimeout time.Duration
	// MaxSessions caps concurrent connections, authenticated or not.
	// Default DefaultMaxSessions.
	MaxSessions int
	// WriteTimeout bounds each line written to a client, so a client that
	// stops reading cannot hold a server goroutine forever. Default
	// DefaultWriteTimeout.
	WriteTimeout time.Duration
	// IdleTimeout, when positive, ends an authenticated session that sends no
	// request for that long, with session.closing. It is re-armed by every
	// request line, so a client that wants a long-lived session (a GUI
	// subscribed to events) sends a cheap request such as status.get more
	// often than this. Zero, the default, keeps sessions open until the
	// client closes them.
	IdleTimeout time.Duration
	// MaxSessionsPerPeer, when positive, caps the authenticated sessions one
	// principal (token SID on Windows, uid elsewhere) may hold at once, so a
	// leaking client cannot take every slot from the others. Zero, the
	// default, applies only MaxSessions.
	MaxSessionsPerPeer int
	// Name and Version identify the server in the hello result.
	Name, Version string
	// Logger receives audit and failure lines. Default slog.Default().
	Logger *slog.Logger
	// Now is the clock used for deadlines. Default time.Now.
	Now func() time.Time
}

// Server accepts local connections, authenticates each one with a hello
// handshake and dispatches requests to registered handlers.
type Server struct {
	o   ServerOptions
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	handlers  map[string]HandlerFunc
	sessions  map[*Session]struct{}
	refusing  map[*Session]struct{}
	perPeer   map[string]int
	listeners map[net.Listener]struct{}
	shutting  bool
	wg        sync.WaitGroup
}

// NewServer validates o and returns a Server.
func NewServer(o ServerOptions) (*Server, error) {
	if o.Token == nil || o.Identify == nil || o.Authorizer == nil {
		return nil, errors.New("ipc: Token, Identify and Authorizer are required")
	}
	if o.HelloTimeout <= 0 {
		o.HelloTimeout = DefaultHelloTimeout
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = DefaultMaxSessions
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = DefaultWriteTimeout
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		o:         o,
		log:       o.Logger,
		ctx:       ctx,
		cancel:    cancel,
		handlers:  make(map[string]HandlerFunc),
		sessions:  make(map[*Session]struct{}),
		refusing:  make(map[*Session]struct{}),
		perPeer:   make(map[string]int),
		listeners: make(map[net.Listener]struct{}),
	}, nil
}

// Handle registers fn for method. It panics on an empty, reserved or
// duplicate method name, because that is a programming error in the host.
func (s *Server) Handle(method string, fn HandlerFunc) {
	if method == "" || method == MethodHello || fn == nil {
		panic(fmt.Sprintf("ipc: invalid handler registration for %q", method))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.handlers[method]; dup {
		panic(fmt.Sprintf("ipc: duplicate handler for %q", method))
	}
	s.handlers[method] = fn
}

func (s *Server) methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.handlers))
	for m := range s.handlers {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handler(method string) HandlerFunc {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handlers[method]
}

// Serve accepts connections from l until l fails or Shutdown is called. It
// returns ErrServerClosed after Shutdown.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.shutting {
		s.mu.Unlock()
		l.Close()
		return ErrServerClosed
	}
	s.listeners[l] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, l)
		s.mu.Unlock()
	}()

	var backoff time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			shutting := s.shutting
			s.mu.Unlock()
			if shutting {
				return ErrServerClosed
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// A transient accept failure (descriptor exhaustion) must not end
			// the channel for the host's lifetime; back off and retry.
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			s.log.Warn("ipc.accept_failed", "error_class", fmt.Sprintf("%T", err))
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		s.accept(conn)
	}
}

// accept registers conn as a session or refuses it over the cap. Sessions are
// counted from accept, not from hello, so unauthenticated connections cannot
// exhaust the host.
func (s *Server) accept(conn net.Conn) {
	sess := s.newSession(conn)
	s.mu.Lock()
	switch {
	case s.shutting:
		s.mu.Unlock()
		conn.Close()
		return
	case len(s.sessions) >= s.o.MaxSessions:
		// Tracked apart from the sessions, so it does not count against the
		// cap, but Shutdown can still close it.
		sess.w = NewLineWriter(&deadlineWriter{conn: conn, timeout: refusalWriteTimeout, now: s.o.Now}, MaxServerLine)
		s.refusing[sess] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.refusing, sess)
				s.mu.Unlock()
			}()
			s.log.Warn("ipc.session_refused", "reason", "session_limit")
			sess.Close(CodeShuttingDown, "session limit")
		}()
		return
	}
	s.sessions[sess] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		defer func() {
			sess.closeQuiet()
			s.mu.Lock()
			delete(s.sessions, sess)
			s.mu.Unlock()
		}()
		sess.serve()
	}()
}

// Shutdown stops accepting, sends session.closing with CodeShuttingDown to
// every session, closes them and waits for their goroutines or ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.shutting = true
	for l := range s.listeners {
		l.Close()
	}
	sessions := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	refusing := make([]*Session, 0, len(s.refusing))
	for sess := range s.refusing {
		refusing = append(refusing, sess)
	}
	s.mu.Unlock()

	// A refusal still writing its notice is dropped without one.
	for _, sess := range refusing {
		sess.conn.Close()
	}

	// Close in parallel: each closing notice may wait up to WriteTimeout on a
	// client that stopped reading.
	for _, sess := range sessions {
		go sess.Close(CodeShuttingDown, "shutting down")
	}
	s.cancel()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// peerKey names the principal a per-peer session cap counts against.
func peerKey(p Peer) string {
	if p.SID != "" {
		return "sid:" + p.SID
	}
	return fmt.Sprintf("uid:%d", p.UID)
}

// claimPeerSlot counts an authenticated session against its principal, or
// reports false when MaxSessionsPerPeer is reached.
func (s *Server) claimPeerSlot(p Peer) bool {
	if s.o.MaxSessionsPerPeer <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := peerKey(p)
	if s.perPeer[key] >= s.o.MaxSessionsPerPeer {
		return false
	}
	s.perPeer[key]++
	return true
}

func (s *Server) releasePeerSlot(p Peer) {
	if s.o.MaxSessionsPerPeer <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := peerKey(p)
	if s.perPeer[key] <= 1 {
		delete(s.perPeer, key)
		return
	}
	s.perPeer[key]--
}

// Session is one client connection.
type Session struct {
	srv  *Server
	conn net.Conn
	w    *LineWriter

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	peerMu sync.Mutex
	peer   Peer

	// onReply, when a handler sets it, runs on the session goroutine right
	// after that handler's response was written (ok true) or could not be
	// (ok false). It lets a handler start streaming notifications only once
	// its response is on the wire.
	onReply func(ok bool)
}

func (s *Server) newSession(conn net.Conn) *Session {
	ctx, cancel := context.WithCancel(s.ctx)
	sess := &Session{srv: s, conn: conn, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	sess.w = NewLineWriter(&deadlineWriter{conn: conn, timeout: s.o.WriteTimeout, now: s.o.Now}, MaxServerLine)
	return sess
}

// Peer returns the identity recorded at hello.
func (ss *Session) Peer() Peer {
	ss.peerMu.Lock()
	defer ss.peerMu.Unlock()
	return ss.peer
}

// Context is cancelled when the session ends or the server shuts down.
func (ss *Session) Context() context.Context { return ss.ctx }

// Done is closed when the session has ended.
func (ss *Session) Done() <-chan struct{} { return ss.done }

// Notify sends a notification. ErrLineTooLong means nothing was written and
// the session is intact, so the caller can drop that one event. Any other
// write failure ends the session.
func (ss *Session) Notify(method string, params any) error {
	select {
	case <-ss.done:
		return errSessionClosed
	default:
	}
	err := ss.w.WriteJSON(Notification{JSONRPC: JSONRPCVersion, Method: method, Params: params})
	if err != nil && !errors.Is(err, ErrLineTooLong) {
		ss.closeQuiet()
	}
	return err
}

// Close sends session.closing with code and reason, then drops the
// connection. Only the first call has any effect.
func (ss *Session) Close(code int, reason string) {
	ss.once.Do(func() {
		_ = ss.w.WriteJSON(Notification{
			JSONRPC: JSONRPCVersion,
			Method:  NotifySessionClosing,
			Params:  ClosingParams{Code: code, Reason: reason},
		})
		ss.finish()
	})
}

func (ss *Session) closeQuiet() { ss.once.Do(ss.finish) }

func (ss *Session) finish() {
	ss.conn.Close()
	ss.cancel()
	close(ss.done)
}

func (ss *Session) reply(id json.RawMessage, result any, e *Error) error {
	if id == nil {
		id = json.RawMessage("null")
	}
	resp := Response{JSONRPC: JSONRPCVersion, ID: id, Result: result, Error: e}
	if e == nil && result == nil {
		resp.Result = struct{}{}
	}
	return ss.w.WriteJSON(resp)
}

// refuse answers a failed hello with CodeUnauthenticated and ends the
// session. The log names a reason class and the peer, never the params.
func (ss *Session) refuse(id json.RawMessage, reason string, peer Peer, cause error) {
	attrs := append([]any{"reason", reason}, peer.LogAttrs()...)
	if cause != nil {
		attrs = append(attrs, "error_class", fmt.Sprintf("%T", cause))
	}
	ss.srv.log.Warn("ipc.auth_refused", attrs...)
	_ = ss.reply(id, nil, &Error{Code: CodeUnauthenticated, Message: "unauthenticated"})
	ss.closeQuiet()
}

// serve runs the hello handshake and then the request loop.
func (ss *Session) serve() {
	o := ss.srv.o
	lr := NewLineReader(ss.conn)

	_ = ss.conn.SetReadDeadline(o.Now().Add(o.HelloTimeout))
	line, err := lr.ReadLine(MaxPreAuthLine)
	if err != nil {
		reason := "read_failed"
		switch {
		case errors.Is(err, ErrLineTooLong):
			reason = "too_large"
		case errors.Is(err, os.ErrDeadlineExceeded):
			reason = "timeout"
		case errors.Is(err, io.EOF):
			reason = "eof"
		}
		// Best effort, for the audit line only. On error the peer is the
		// unknown identity, never what Identify returned beside the error:
		// a zero Peer reads as uid 0.
		peer, ierr := o.Identify(ss.conn)
		if ierr != nil {
			peer = Peer{UID: -1, GID: -1}
		}
		ss.refuse(nil, reason, peer, nil)
		return
	}

	// Parse first so a refusal can echo the id, but decide nothing on the
	// content until both identity checks have passed.
	var req Request
	parseErr := json.Unmarshal(line, &req)
	id := validID(req.ID)

	// Identify after the line is read: on Windows the client identity is
	// that of the last message read from the pipe.
	peer, err := o.Identify(ss.conn)
	if err != nil {
		ss.refuse(id, "identify_failed", Peer{UID: -1, GID: -1}, err)
		return
	}
	if err := o.Authorizer.Authorize(peer); err != nil {
		ss.refuse(id, "peer_refused", peer, err)
		return
	}
	if parseErr != nil || req.JSONRPC != JSONRPCVersion {
		ss.refuse(id, "malformed", peer, nil)
		return
	}
	if req.Method != MethodHello || id == nil {
		ss.refuse(id, "not_hello", peer, nil)
		return
	}
	var hp HelloParams
	if err := json.Unmarshal(req.Params, &hp); err != nil {
		ss.refuse(id, "malformed", peer, nil)
		return
	}
	if hp.Protocol != ProtocolVersion {
		ss.srv.log.Warn("ipc.auth_refused", append([]any{"reason", "unsupported_protocol"}, peer.LogAttrs()...)...)
		_ = ss.reply(id, nil, &Error{
			Code:    CodeUnsupportedProtocol,
			Message: "unsupported protocol",
			Data:    map[string]int{"min": ProtocolVersion, "max": ProtocolVersion},
		})
		ss.closeQuiet()
		return
	}
	if !TokenEqual(hp.Token, o.Token()) {
		ss.refuse(id, "bad_token", peer, nil)
		return
	}

	if !ss.srv.claimPeerSlot(peer) {
		ss.srv.log.Warn("ipc.session_refused", append([]any{"reason", "peer_session_limit"}, peer.LogAttrs()...)...)
		ss.Close(CodeShuttingDown, "session limit")
		return
	}
	defer ss.srv.releasePeerSlot(peer)

	_ = ss.conn.SetReadDeadline(time.Time{})
	ss.peerMu.Lock()
	ss.peer = peer
	ss.peerMu.Unlock()
	if err := ss.reply(id, HelloResult{
		Protocol: ProtocolVersion,
		Server:   Endpoint{Name: o.Name, Version: o.Version},
		Methods:  ss.srv.methods(),
	}, nil); err != nil {
		return
	}
	ss.srv.log.Info("ipc.session_open", peer.LogAttrs()...)
	defer ss.srv.log.Info("ipc.session_closed", peer.LogAttrs()...)

	for {
		if o.IdleTimeout > 0 {
			_ = ss.conn.SetReadDeadline(o.Now().Add(o.IdleTimeout))
		}
		line, err := lr.ReadLine(MaxRequestLine)
		if o.IdleTimeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			ss.srv.log.Info("ipc.session_idle", peer.LogAttrs()...)
			ss.Close(CodeShuttingDown, "idle timeout")
			return
		}
		if errors.Is(err, ErrLineTooLong) {
			if ss.reply(nil, nil, &Error{Code: CodeInvalidRequest, Message: "request too large"}) != nil {
				return
			}
			continue
		}
		if err != nil {
			return
		}
		if ss.dispatch(line) != nil {
			return
		}
	}
}

// dispatch handles one request line. A returned error is a write failure
// and ends the session.
func (ss *Session) dispatch(line []byte) error {
	if !json.Valid(line) {
		return ss.reply(nil, nil, &Error{Code: CodeParse, Message: "parse error"})
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return ss.reply(nil, nil, &Error{Code: CodeInvalidRequest, Message: "invalid request"})
	}
	id := validID(req.ID)
	if req.ID != nil && id == nil {
		return ss.reply(nil, nil, &Error{Code: CodeInvalidRequest, Message: "invalid request"})
	}
	if req.JSONRPC != JSONRPCVersion || req.Method == "" {
		return ss.reply(id, nil, &Error{Code: CodeInvalidRequest, Message: "invalid request"})
	}
	if id == nil {
		// Client notifications carry nothing this protocol acts on.
		return nil
	}
	if req.Method == MethodHello {
		return ss.reply(id, nil, &Error{Code: CodeInvalidRequest, Message: "already authenticated"})
	}
	fn := ss.srv.handler(req.Method)
	if fn == nil {
		return ss.reply(id, nil, &Error{Code: CodeMethodNotFound, Message: "method not found"})
	}
	ss.onReply = nil
	result, err := ss.call(fn, req.Method, req.Params)
	after := ss.onReply
	ss.onReply = nil
	if err != nil {
		if after != nil {
			after(false)
		}
		var e *Error
		if !errors.As(err, &e) {
			ss.srv.log.Error("ipc.handler_failed", "method", req.Method, "error_class", fmt.Sprintf("%T", err))
			e = &Error{Code: CodeInternal, Message: "internal error"}
		}
		return ss.reply(id, nil, e)
	}
	err = ss.reply(id, result, nil)
	if after != nil {
		after(err == nil)
	}
	if errors.Is(err, ErrLineTooLong) {
		ss.srv.log.Error("ipc.result_too_large", "method", req.Method)
		return ss.reply(id, nil, &Error{Code: CodeInternal, Message: "internal error"})
	}
	return err
}

// call runs a handler and turns a panic into an internal error, so one
// faulty handler cannot take the host process down.
func (ss *Session) call(fn HandlerFunc, method string, params json.RawMessage) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			ss.srv.log.Error("ipc.handler_panic", "method", method, "panic_class", fmt.Sprintf("%T", r))
			result, err = nil, errors.New("handler panic")
		}
	}()
	return fn(ss.ctx, ss, params)
}

// validID returns id if it is a JSON number or string, else nil.
func validID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return nil
	}
	switch id[0] {
	case '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return id
	}
	return nil
}

// deadlineWriter arms a write deadline before every write. LineWriter calls
// it under its mutex, so concurrent writers never race on the deadline.
type deadlineWriter struct {
	conn    net.Conn
	timeout time.Duration
	now     func() time.Time
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	_ = d.conn.SetWriteDeadline(d.now().Add(d.timeout))
	return d.conn.Write(p)
}
