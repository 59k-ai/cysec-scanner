// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// requireWindows skips a test whose precondition is missing, or fails it
// when CYSEC_REQUIRE_IPC_WINDOWS=1 says it must run.
func requireWindows(t *testing.T, ok bool, why string) {
	t.Helper()
	if ok {
		return
	}
	if os.Getenv("CYSEC_REQUIRE_IPC_WINDOWS") == "1" {
		t.Fatalf("%s and CYSEC_REQUIRE_IPC_WINDOWS=1 is set", why)
	}
	t.Skip(why)
}

func requireElevated(t *testing.T) {
	t.Helper()
	requireWindows(t, windows.GetCurrentProcessToken().IsElevated(), "needs an elevated administrator")
}

func pipeName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return `\\.\pipe\scanner-ipc-test-` + hex.EncodeToString(b)
}

func listenPipe(t *testing.T, name, sddl string) Listener {
	t.Helper()
	l, err := Listen(ListenOptions{Address: name, Pipe: PipeOptions{SDDL: sddl}})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func sameUserSDDL(t *testing.T) string {
	t.Helper()
	sid, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	return SameUserPipeSDDL(sid)
}

// serverPeer accepts one connection, reads the client's first line (the
// impersonation context is that of the last message read) and identifies it.
func serverPeer(t *testing.T, l Listener) (Peer, error) {
	t.Helper()
	type res struct {
		p   Peer
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			ch <- res{err: err}
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
			ch <- res{err: err}
			return
		}
		p, err := l.Identify()(c)
		ch <- res{p, err}
	}()
	select {
	case r := <-ch:
		return r.p, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("server timed out")
		return Peer{}, nil
	}
}

func dialHello(t *testing.T, name string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, name)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPipeListen(t *testing.T) {
	name := pipeName(t)
	l := listenPipe(t, name, sameUserSDDL(t))
	if got := l.Addr().Network(); got != "pipe" {
		t.Fatalf("network %q, want pipe", got)
	}
	ch := make(chan struct{})
	var p Peer
	var err error
	go func() { p, err = serverPeer(t, l); close(ch) }()
	dialHello(t, name)
	<-ch
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	sid, _ := CurrentUserSID()
	if p.SID != sid || p.PID != os.Getpid() || p.UID != -1 || p.GID != -1 {
		t.Fatalf("peer %+v, want sid %s pid %d", p, sid, os.Getpid())
	}
	if err := SameUserAuthorizer().Authorize(p); err != nil {
		t.Fatalf("SameUserAuthorizer: %v", err)
	}

	for _, bad := range []ListenOptions{
		{Address: name + "-nosddl"},
		{Address: `C:\temp\x`, Pipe: PipeOptions{SDDL: AdminPipeSDDL}},
		{Address: `\\.\pipe\`, Pipe: PipeOptions{SDDL: AdminPipeSDDL}},
	} {
		if _, err := Listen(bad); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("%+v: err %v, want ErrInvalidAddress", bad, err)
		}
	}
	if _, err := Dial(context.Background(), `\\server\pipe\x`); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("remote dial address accepted: %v", err)
	}
}

func TestPipeFirstInstance(t *testing.T) {
	name := pipeName(t)
	listenPipe(t, name, sameUserSDDL(t))
	l2, err := Listen(ListenOptions{Address: name, Pipe: PipeOptions{SDDL: sameUserSDDL(t)}})
	if err == nil {
		_ = l2.Close()
		t.Fatal("a second listener on the same name succeeded")
	}
	if !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("err %v, want ErrAddressInUse", err)
	}
}

// TestPipeSDDL reads the DACL back from the kernel. The creator's generic
// rights are mapped to specific ones when the pipe is created (GA becomes
// FILE_ALL_ACCESS), so the ACEs are compared rather than the SDDL text.
// Only the first instance is created with this DACL by design: BA lacks
// FILE_CREATE_PIPE_INSTANCE, so an administrator cannot add an instance.
func TestPipeSDDL(t *testing.T) {
	const fileAllAccess = 0x001f01ff
	requireElevated(t)
	name := pipeName(t)
	l := listenPipe(t, name, AdminPipeSDDL)
	go func() { _, _ = serverPeer(t, l) }()
	c := dialHello(t, name)
	h := windows.Handle(c.(interface{ Fd() uintptr }).Fd())
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetSecurityInfo: %v", err)
	}
	ctl, _, err := sd.Control()
	if err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL not protected: %v %v", ctl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	type ace struct {
		typ  uint8
		mask uint32
		sid  string
	}
	want := []ace{
		{windows.ACCESS_DENIED_ACE_TYPE, fileAllAccess, "S-1-5-2"},
		{windows.ACCESS_ALLOWED_ACE_TYPE, fileAllAccess, "S-1-5-18"},
		{windows.ACCESS_ALLOWED_ACE_TYPE, 0x0012019b, "S-1-5-32-544"},
	}
	if int(dacl.AceCount) != len(want) {
		t.Fatalf("%d ACEs, want %d (%s)", dacl.AceCount, len(want), sd.String())
	}
	for i, w := range want {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &a); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart)).String()
		if a.Header.AceType != w.typ || uint32(a.Mask) != w.mask || sid != w.sid {
			t.Fatalf("ACE %d = {%d %#x %s}, want {%d %#x %s}", i, a.Header.AceType, a.Mask, sid, w.typ, w.mask, w.sid)
		}
	}
}

// TestPipeRejectRemote proves the remote path is closed: go-winio always
// creates server instances with FILE_PIPE_REJECT_REMOTE_CLIENTS, and the
// DACL denies network logons, so even the loopback SMB path fails. Its
// value is a runner result; a host without the SMB server fails the dial
// for a weaker reason, which the local dial below rules in or out.
func TestPipeRejectRemote(t *testing.T) {
	name := pipeName(t)
	l := listenPipe(t, name, sameUserSDDL(t))
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	dialHello(t, name)
	remote := `\\localhost\pipe\` + strings.TrimPrefix(name, `\\.\pipe\`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := winio.DialPipeAccessImpLevel(ctx, remote, windows.GENERIC_READ|windows.FILE_WRITE_DATA, winio.PipeImpLevelIdentification)
	if err == nil {
		_ = c.Close()
		t.Fatal("a remote-path client connected")
	}
}

func TestPeerWindowsAdmin(t *testing.T) {
	requireElevated(t)
	name := pipeName(t)
	l := listenPipe(t, name, AdminPipeSDDL)
	ch := make(chan struct{})
	var p Peer
	var err error
	go func() { p, err = serverPeer(t, l); close(ch) }()
	dialHello(t, name)
	<-ch
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if !p.Admin {
		t.Fatalf("elevated peer not marked admin: %+v", p)
	}
	if err := AdminAuthorizer(-1).Authorize(p); err != nil {
		t.Fatalf("AdminAuthorizer refused an elevated admin: %v", err)
	}
}

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken   = advapi32.NewProc("CreateRestrictedToken")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
)

// restrictedToken returns a copy of the process token in which
// BUILTIN\Administrators is deny-only, as in a UAC-filtered admin token.
func restrictedToken(t *testing.T) windows.Token {
	t.Helper()
	var proc windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_IMPERSONATE, &proc)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	ba, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disable := []windows.SIDAndAttributes{{Sid: ba}}
	var out windows.Token
	r, _, e := procCreateRestrictedToken.Call(uintptr(proc), 0,
		1, uintptr(unsafe.Pointer(&disable[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		t.Fatalf("CreateRestrictedToken: %v", e)
	}
	return out
}

// asRestricted runs f on a locked OS thread that impersonates tok.
func asRestricted(t *testing.T, tok windows.Token, f func()) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if r, _, e := procImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
			runtime.UnlockOSThread()
			done <- e
			return
		}
		f()
		if err := windows.RevertToSelf(); err != nil {
			done <- err // thread stays locked and is discarded
			return
		}
		runtime.UnlockOSThread()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatalf("impersonation: %v", err)
	}
}

func TestPeerWindowsRestrictedRefused(t *testing.T) {
	requireElevated(t)
	tok := restrictedToken(t)
	defer tok.Close()

	adminName := pipeName(t)
	listenPipe(t, adminName, AdminPipeSDDL)
	var dialErr error
	asRestricted(t, tok, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := Dial(ctx, adminName)
		if err == nil {
			_ = c.Close()
		}
		dialErr = err
	})
	if !errors.Is(dialErr, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("deny-only admin dial: err %v, want access denied", dialErr)
	}

	userName := pipeName(t)
	l := listenPipe(t, userName, sameUserSDDL(t))
	ch := make(chan struct{})
	var p Peer
	var err error
	go func() { p, err = serverPeer(t, l); close(ch) }()
	asRestricted(t, tok, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, derr := Dial(ctx, userName)
		if derr != nil {
			err = derr
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = c.Write([]byte("x\n"))
	})
	<-ch
	if err != nil {
		t.Fatalf("restricted peer: %v", err)
	}
	if p.Admin {
		t.Fatal("a deny-only administrators SID counted as membership")
	}
	if err := AdminAuthorizer(-1).Authorize(p); err == nil {
		t.Fatal("AdminAuthorizer accepted a UAC-filtered admin")
	}
}

// fdConn is a net.Conn stand-in that exposes a pipe handle.
type fdConn struct{ net.Conn }

func (fdConn) Fd() uintptr { return 0 }

func TestImpersonationThreadDiscipline(t *testing.T) {
	saved := impersonationHooks
	defer func() { impersonationHooks = saved }()

	var locks, unlocks int
	impersonationHooks.lock = func() { locks++ }
	impersonationHooks.unlock = func() { unlocks++ }
	impersonationHooks.impersonate = func(windows.Handle) error { return nil }
	impersonationHooks.openToken = func(*windows.Token) error { return errors.New("no token") }

	impersonationHooks.revert = func() error { return errors.New("revert failed") }
	if _, err := identifyPeer(fdConn{}); err == nil {
		t.Fatal("a failed revert was not reported")
	}
	if locks != 1 || unlocks != 0 {
		t.Fatalf("after failed revert: %d locks %d unlocks, want 1 0", locks, unlocks)
	}

	locks, unlocks = 0, 0
	impersonationHooks.revert = func() error { return nil }
	if _, err := identifyPeer(fdConn{}); err == nil {
		t.Fatal("a missing token was not reported")
	}
	if locks != 1 || unlocks != 1 {
		t.Fatalf("after clean revert: %d locks %d unlocks, want 1 1", locks, unlocks)
	}

	locks, unlocks = 0, 0
	impersonationHooks.impersonate = func(windows.Handle) error { return windows.ERROR_ACCESS_DENIED }
	if _, err := identifyPeer(fdConn{}); err == nil {
		t.Fatal("a failed impersonation was not reported")
	}
	if locks != 1 || unlocks != 1 {
		t.Fatalf("after failed impersonation: %d locks %d unlocks, want 1 1", locks, unlocks)
	}

	if _, err := identifyPeer(struct{ net.Conn }{}); err == nil {
		t.Fatal("a conn without a handle was identified")
	}
}
