// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/ipc"
	"github.com/59k-ai/cysec-scanner/progress"
)

var refhostBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "refhost-bin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	refhostBin = filepath.Join(dir, "ipc-refhost")
	if runtime.GOOS == "windows" {
		refhostBin += ".exe"
	}
	build := exec.Command("go", "build", "-o", refhostBin, ".")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build reference host:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// endpoint returns a fresh address and token file path for one test.
func endpoint(t *testing.T) (addr, tokenFile string) {
	t.Helper()
	tokenFile = filepath.Join(t.TempDir(), "token")
	if runtime.GOOS == "windows" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		return `\\.\pipe\refhost-test-` + hex.EncodeToString(b[:]), tokenFile
	}
	// The per-test temp dir on macOS is too deep for the sun_path limit.
	d, err := os.MkdirTemp("/tmp", "rh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d, "r.sock"), tokenFile
}

type refhost struct {
	t         *testing.T
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	addr      string
	tokenFile string
	stdout    *lockedBuffer
	stderr    *lockedBuffer
	exited    chan error
}

func startRefhost(t *testing.T, addr, tokenFile string, extra ...string) *refhost {
	t.Helper()
	args := append([]string{"--address", addr, "--token-file", tokenFile, "--exit-on-stdin-eof"}, extra...)
	cmd := exec.Command(refhostBin, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	r := &refhost{t: t, cmd: cmd, stdin: stdin, addr: addr, tokenFile: tokenFile,
		stdout: &lockedBuffer{}, stderr: &lockedBuffer{}, exited: make(chan error, 1)}
	cmd.Stderr = r.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() {
		br := bufio.NewReader(out)
		line, _ := br.ReadString('\n')
		ready <- line
		_, _ = io.Copy(r.stdout, br)
	}()
	go func() { r.exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = stdin.Close()
		select {
		case <-r.exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-r.exited
		}
	})
	select {
	case line := <-ready:
		if line != "READY "+addr+"\n" {
			t.Fatalf("want READY line, got %q (stderr: %s)", line, r.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("no READY line (stderr: %s)", r.stderr.String())
	}
	return r
}

// stop asks the host to exit the way an operator or a test harness would and
// waits for a clean exit.
func (r *refhost) stop() {
	r.t.Helper()
	if runtime.GOOS == "windows" {
		_ = r.stdin.Close()
	} else {
		_ = r.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case err := <-r.exited:
		r.exited <- err
		if err != nil {
			r.t.Fatalf("reference host exited with %v (stderr: %s)", err, r.stderr.String())
		}
	case <-time.After(5 * time.Second):
		r.t.Fatal("reference host did not stop")
	}
}

func (r *refhost) token() string {
	r.t.Helper()
	b, err := os.ReadFile(r.tokenFile)
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *refhost) client(token string) (*ipc.Client, ipc.HelloResult, error) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := ipc.Dial(ctx, r.addr)
	if err != nil {
		r.t.Fatalf("dial: %v", err)
	}
	c := ipc.NewClient(conn)
	r.t.Cleanup(func() { c.Close() })
	res, err := c.Hello(ctx, token, ipc.Endpoint{Name: "refhost-test", Version: "0"})
	return c, res, err
}

func (r *refhost) mustClient() *ipc.Client {
	r.t.Helper()
	c, _, err := r.client(r.token())
	if err != nil {
		r.t.Fatalf("hello: %v", err)
	}
	return c
}

func call(t *testing.T, c *ipc.Client, method string, params, out any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.Call(ctx, method, params, out)
}

func wantCode(t *testing.T, err error, code int) *ipc.Error {
	t.Helper()
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want error %d, got %v", code, err)
	}
	return e
}

func next(t *testing.T, c *ipc.Client) ipc.Notification {
	t.Helper()
	select {
	case n, ok := <-c.Notifications():
		if !ok {
			t.Fatal("notification stream closed")
		}
		return n
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a notification")
	}
	return ipc.Notification{}
}

func params[T any](t *testing.T, n ipc.Notification) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(n.Params.(json.RawMessage), &v); err != nil {
		t.Fatalf("decode %s: %v", n.Method, err)
	}
	return v
}

// subscribeIdle subscribes on an idle host and consumes the empty snapshot.
func subscribeIdle(t *testing.T, c *ipc.Client) {
	t.Helper()
	var sub ipc.SubscribeResult
	if err := call(t, c, ipc.MethodEventsSubscribe, nil, &sub); err != nil || sub.Run != nil {
		t.Fatalf("subscribe %+v %v", sub, err)
	}
	if n := next(t, c); n.Method != ipc.NotifySnapshotDone {
		t.Fatalf("want snapshot.done, got %s", n.Method)
	}
}

// collect reads live notifications until the run ends and returns the
// progress events and the ended outcome.
func collect(t *testing.T, c *ipc.Client, runID string) ([]progress.Event, string) {
	t.Helper()
	var evs []progress.Event
	for {
		n := next(t, c)
		switch n.Method {
		case ipc.NotifyProgress:
			p := params[ipc.ProgressParams](t, n)
			if p.RunID != runID || p.Replay {
				t.Fatalf("unexpected progress %+v", p)
			}
			evs = append(evs, p.Event)
		case ipc.NotifyRunState:
			s := params[ipc.RunStateParams](t, n)
			if s.RunID != runID {
				t.Fatalf("run.state for %q, want %q", s.RunID, runID)
			}
			if s.State == "ended" {
				return evs, s.Outcome
			}
		}
	}
}

// writeScript copies the shared GUI fixture into a temp file, optionally
// replacing its final scan_end status.
func writeScript(t *testing.T, status string) (path string, events []progress.Event) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "gui", "tests", "fixtures", "ndjson-detailed.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e progress.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Kind == progress.ScanEnd && status != "" {
			e.ScanEnd.Status = status
		}
		events = append(events, e)
		enc, _ := json.Marshal(e)
		out.Write(enc)
		out.WriteByte('\n')
	}
	path = filepath.Join(t.TempDir(), "script.ndjson")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, events
}

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43,}$`)

func TestRefhostReady(t *testing.T) {
	addr, tokenFile := endpoint(t)
	r := startRefhost(t, addr, tokenFile)
	tok := r.token()
	if !tokenRE.MatchString(tok) {
		t.Fatalf("token %q is not a bare base64url token", tok)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(tokenFile)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("token file mode %v", fi.Mode().Perm())
		}
	}
	_, hello, err := r.client(tok)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if hello.Server.Name != "reference-host" || hello.Protocol != ipc.ProtocolVersion {
		t.Fatalf("hello result %+v", hello)
	}
	r.stop()
	if s := r.stdout.String(); s != "" {
		t.Fatalf("stdout carried more than the READY line: %q", s)
	}
}

func TestRefhostScriptedRun(t *testing.T) {
	for _, tc := range []struct{ status, outcome string }{
		{"completed", "completed"},
		{"failed", "failed"},
		{"", "cancelled"}, // the fixture as shipped ends with a cancelled scan
	} {
		t.Run(tc.outcome, func(t *testing.T) {
			script, want := writeScript(t, tc.status)
			addr, tokenFile := endpoint(t)
			r := startRefhost(t, addr, tokenFile, "--script", script, "--step", "5ms")
			c := r.mustClient()
			subscribeIdle(t, c)
			var st ipc.StartResult
			if err := call(t, c, ipc.MethodRunStart, nil, &st); err != nil || st.RunID == "" {
				t.Fatalf("run.start %+v %v", st, err)
			}
			if s := params[ipc.RunStateParams](t, next(t, c)); s.State != "started" || s.Trigger != "manual" {
				t.Fatalf("started: %+v", s)
			}
			got, outcome := collect(t, c, st.RunID)
			if outcome != tc.outcome {
				t.Fatalf("outcome %q, want %q", outcome, tc.outcome)
			}
			if len(got) != len(want) {
				t.Fatalf("got %d events, want %d", len(got), len(want))
			}
			for i := range want {
				if got[i].Kind != want[i].Kind || got[i].Seq != i {
					t.Fatalf("event %d: got %s seq %d, want %s seq %d", i, got[i].Kind, got[i].Seq, want[i].Kind, i)
				}
			}
			if got[0].Scan == nil || strings.Join(got[0].Scan.Scope, ",") != strings.Join(want[0].Scan.Scope, ",") {
				t.Fatalf("scan_start scope %+v", got[0].Scan)
			}
			r.stop()
		})
	}
}

func TestRefhostAutostart(t *testing.T) {
	addr, tokenFile := endpoint(t)
	r := startRefhost(t, addr, tokenFile, "--autostart", "--step", "100ms")
	c := r.mustClient()
	var st ipc.StatusResult
	if err := call(t, c, ipc.MethodStatusGet, nil, &st); err != nil || st.State != "running" || st.Run == nil || st.Run.Trigger != "schedule" {
		t.Fatalf("status %+v %v", st, err)
	}
	var sub ipc.SubscribeResult
	if err := call(t, c, ipc.MethodEventsSubscribe, nil, &sub); err != nil || sub.Run == nil || sub.Run.RunID != st.Run.RunID {
		t.Fatalf("mid-run subscribe %+v %v", sub, err)
	}
	e := wantCode(t, call(t, c, ipc.MethodRunStart, nil, nil), ipc.CodeRunInProgress)
	if data, _ := e.Data.(map[string]any); data["run_id"] != st.Run.RunID {
		t.Fatalf("run-in-progress data %#v", e.Data)
	}
	r.stop()
}

func TestRefhostCancel(t *testing.T) {
	addr, tokenFile := endpoint(t)
	r := startRefhost(t, addr, tokenFile, "--step", "50ms")
	c := r.mustClient()
	subscribeIdle(t, c)
	var st ipc.StartResult
	if err := call(t, c, ipc.MethodRunStart, nil, &st); err != nil {
		t.Fatal(err)
	}
	for seen := 0; seen < 3; {
		if next(t, c).Method == ipc.NotifyProgress {
			seen++
		}
	}
	var cr ipc.CancelResult
	if err := call(t, c, ipc.MethodRunCancel, ipc.CancelParams{RunID: st.RunID}, &cr); err != nil || !cr.Accepted {
		t.Fatalf("cancel %+v %v", cr, err)
	}
	evs, outcome := collect(t, c, st.RunID)
	if outcome != "cancelled" {
		t.Fatalf("outcome %q", outcome)
	}
	last := evs[len(evs)-1]
	if last.Kind != progress.ScanEnd || last.ScanEnd == nil || last.ScanEnd.Status != "cancelled" {
		t.Fatalf("last event %+v", last)
	}
	wantCode(t, call(t, c, ipc.MethodRunCancel, ipc.CancelParams{RunID: st.RunID}, nil), ipc.CodeNotRunning)
	r.stop()
}

func TestRefhostRestartRotatesToken(t *testing.T) {
	addr, tokenFile := endpoint(t)
	r := startRefhost(t, addr, tokenFile)
	first := r.token()
	r.mustClient()
	r.stop()
	if _, err := os.Stat(tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token file left behind after a clean exit: %v", err)
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Lstat(addr); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket left behind after a clean exit: %v", err)
		}
	}

	r2 := startRefhost(t, addr, tokenFile)
	second := r2.token()
	if second == first {
		t.Fatal("restart reused the token")
	}
	if _, _, err := r2.client(first); err == nil {
		t.Fatal("old token accepted after restart")
	} else {
		wantCode(t, err, ipc.CodeUnauthenticated)
	}
	r2.mustClient()
	r2.stop()
}

func TestRefhostScopeParams(t *testing.T) {
	addr, tokenFile := endpoint(t)
	r := startRefhost(t, addr, tokenFile, "--step", "20ms")
	c := r.mustClient()
	for _, bad := range []string{
		`{"cidrs":"10.0.0.0/30"}`,
		`{"cidrs":["not-a-cidr"]}`,
		`{"bogus":1}`,
		`{"ports":22}`,
		`[1]`,
		`"x"`,
	} {
		wantCode(t, call(t, c, ipc.MethodRunStart, json.RawMessage(bad), nil), ipc.CodeInvalidParams)
	}
	subscribeIdle(t, c)
	var st ipc.StartResult
	err := call(t, c, ipc.MethodRunStart, json.RawMessage(`{"cidrs":["10.0.0.0/30"],"ports":"22","probe_fragile":false}`), &st)
	if err != nil {
		t.Fatal(err)
	}
	for {
		n := next(t, c)
		if n.Method != ipc.NotifyProgress {
			continue
		}
		p := params[ipc.ProgressParams](t, n)
		if p.Event.Kind != progress.ScanStart || p.Event.Scan == nil || strings.Join(p.Event.Scan.Scope, ",") != "10.0.0.0/30" {
			t.Fatalf("first event %+v scan %+v", p.Event, p.Event.Scan)
		}
		break
	}
	_ = call(t, c, ipc.MethodRunCancel, ipc.CancelParams{RunID: st.RunID}, nil)
	r.stop()
}

func TestRefhostDoesNotLinkEngine(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasSuffix(dep, "cysec-scanner/scanner") || strings.Contains(dep, "cysec-scanner/scanner/") ||
			strings.Contains(dep, "cysec-scanner/cmd/") {
			t.Fatalf("reference host links %s", dep)
		}
	}
}
