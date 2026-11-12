// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

// requireRoot skips a root-only test, or fails it when the environment says
// the root half must run.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	if os.Getenv("CYSEC_REQUIRE_IPC_ROOT") == "1" {
		t.Fatal("this test needs root and CYSEC_REQUIRE_IPC_ROOT=1 is set")
	}
	t.Skip("needs root")
}

var (
	helperOnce sync.Once
	helperPath string
	helperErr  error
)

// helperBinary returns a copy of the test binary that an unprivileged uid can
// execute: the build directory of go test is private to its owner.
func helperBinary(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			helperErr = err
			return
		}
		dir, err := os.MkdirTemp("/tmp", "ipcbin")
		if err != nil {
			helperErr = err
			return
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			helperErr = err
			return
		}
		src, err := os.Open(exe)
		if err != nil {
			helperErr = err
			return
		}
		defer src.Close()
		helperPath = filepath.Join(dir, "ipc.test")
		dst, err := os.OpenFile(helperPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			helperErr = err
			return
		}
		if _, err := io.Copy(dst, src); err != nil {
			helperErr = err
		}
		if err := dst.Close(); err != nil && helperErr == nil {
			helperErr = err
		}
	})
	if helperErr != nil {
		t.Fatalf("helper binary: %v", helperErr)
	}
	return helperPath
}

// runHelper re-execs the test binary as a dial helper. cred nil runs it as
// the current user. It returns the exit code and the combined output.
func runHelper(t *testing.T, addr string, cred *syscall.Credential) (int, string) {
	t.Helper()
	bin := helperBinary(t)
	cmd := exec.Command(bin, "-test.run=^$")
	cmd.Env = append(os.Environ(), "IPC_TEST_HELPER=dial", "IPC_TEST_ADDR="+addr)
	cmd.Dir = "/"
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out.String()
		}
		if err != nil {
			t.Fatalf("helper: %v", err)
		}
		return 0, out.String()
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("helper timed out")
		return -1, ""
	}
}

// helperPeer starts a helper under cred and returns the identity the
// listener reads for its connection.
func helperPeer(t *testing.T, l Listener, addr string, cred *syscall.Credential) Peer {
	t.Helper()
	type res struct {
		code int
		out  string
	}
	ch := make(chan res, 1)
	go func() {
		code, out := runHelper(t, addr, cred)
		ch <- res{code, out}
	}()
	c := acceptOne(t, l)
	p, err := l.Identify()(c)
	_ = c.Close()
	r := <-ch
	if r.code != 0 {
		t.Fatalf("helper exit %d: %s", r.code, r.out)
	}
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	return p
}

func TestPeerSameUser(t *testing.T) {
	addr := filepath.Join(shortDir(t), "s.sock")
	l, err := Listen(userOpts(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := dialT(t, addr); err != nil {
		t.Fatal(err)
	}
	p, err := l.Identify()(acceptOne(t, l))
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if p.UID != os.Geteuid() || p.PID != os.Getpid() {
		t.Fatalf("peer uid %d pid %d, want %d %d", p.UID, p.PID, os.Geteuid(), os.Getpid())
	}
	if !slices.Contains(p.Groups, os.Getegid()) {
		t.Fatalf("groups %v miss egid %d", p.Groups, os.Getegid())
	}
	if p.SID != "" {
		t.Fatalf("sid %q on unix", p.SID)
	}
	if err := SameUserAuthorizer().Authorize(p); err != nil {
		t.Fatalf("SameUserAuthorizer refused the same user: %v", err)
	}
}

func TestPeerNonAdmin(t *testing.T) {
	requireRoot(t)
	const adminGID = 4242
	base := shortDir(t)
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	addr := filepath.Join(base, "s.sock")
	l, err := Listen(ListenOptions{Address: addr, Unix: UnixOptions{
		DirOwnerUID: 0, DirGID: -1, SocketGID: -1, SocketMode: 0o666,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	nobody := helperPeer(t, l, addr, &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}})
	if nobody.UID != 65534 || nobody.GID != 65534 {
		t.Fatalf("helper peer %d:%d, want 65534:65534", nobody.UID, nobody.GID)
	}
	if err := AdminAuthorizer(adminGID).Authorize(nobody); err == nil {
		t.Fatal("AdminAuthorizer accepted an unprivileged peer")
	}
	if err := SameUserAuthorizer().Authorize(nobody); err == nil {
		t.Fatal("SameUserAuthorizer accepted another uid")
	}

	if _, err := dialT(t, addr); err != nil {
		t.Fatal(err)
	}
	root, err := l.Identify()(acceptOne(t, l))
	if err != nil {
		t.Fatal(err)
	}
	if err := AdminAuthorizer(adminGID).Authorize(root); err != nil {
		t.Fatalf("AdminAuthorizer refused root: %v", err)
	}
}
