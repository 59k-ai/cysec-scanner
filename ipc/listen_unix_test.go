// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain doubles as the entry point of the dial helper: a re-exec of the
// test binary under another uid/gid connects to a socket and reports through
// its exit code, so peer checks are exercised against a real foreign process.
func TestMain(m *testing.M) {
	if os.Getenv("IPC_TEST_HELPER") == "dial" {
		os.Exit(helperDial(os.Getenv("IPC_TEST_ADDR")))
	}
	os.Exit(m.Run())
}

func helperDial(addr string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := Dial(ctx, addr)
	if err != nil {
		_, _ = os.Stderr.WriteString("dial: " + err.Error() + "\n")
		return 2
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("x\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	return 0
}

// shortDir returns a private directory under /tmp: the per-test temp dir on
// macOS is too deep for the 104-byte sun_path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// userOpts is the policy for a directory owned by the test user, with group
// checks disabled.
func userOpts(addr string) ListenOptions {
	return ListenOptions{Address: addr, Unix: UnixOptions{
		DirOwnerUID: os.Geteuid(), DirGID: -1, SocketGID: -1, SocketMode: 0o600,
	}}
}

func statOwner(t *testing.T, path string) (uid, gid int, mode os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid), fi.Mode()
}

// acceptOne accepts a single connection or fails after five seconds.
func acceptOne(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := l.Accept()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("accept: %v", r.err)
		}
		t.Cleanup(func() { _ = r.c.Close() })
		return r.c
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
		return nil
	}
}

func dialT(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr)
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return c, err
}

// staleSocket leaves a socket file behind with no listener, as a crash does.
func staleSocket(t *testing.T, addr string) {
	t.Helper()
	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ul.SetUnlinkOnClose(false)
	_ = ul.Close()
	if fi, err := os.Lstat(addr); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale socket not left behind: %v", err)
	}
}

func TestListenUnix(t *testing.T) {
	dir := shortDir(t)
	addr := filepath.Join(dir, "s.sock")
	l, err := Listen(userOpts(addr))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if got := l.Addr().Network(); got != "unix" {
		t.Fatalf("network %q, want unix", got)
	}
	if l.Identify() == nil {
		t.Fatal("Identify is nil")
	}
	_, _, mode := statOwner(t, addr)
	if mode&os.ModeSocket == 0 || mode.Perm() != 0o600 {
		t.Fatalf("socket mode %v, want socket 0600", mode)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(addr); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still present after Close: %v", err)
	}
}

func TestUnixPathPolicy(t *testing.T) {
	t.Run("invalidAddress", func(t *testing.T) {
		for _, a := range []string{
			"rel/s.sock",
			"@abstract",
			"/" + strings.Repeat("a", 103),
			"/tmp/a\x00b",
			"",
		} {
			if _, err := Listen(userOpts(a)); !errors.Is(err, ErrInvalidAddress) {
				t.Errorf("%q: err %v, want ErrInvalidAddress", a, err)
			}
		}
	})

	t.Run("groupOrWorldWritable", func(t *testing.T) {
		for _, m := range []os.FileMode{0o770, 0o702, 0o777} {
			dir := shortDir(t)
			if err := os.Chmod(dir, m); err != nil {
				t.Fatal(err)
			}
			if _, err := Listen(userOpts(filepath.Join(dir, "s.sock"))); !errors.Is(err, ErrUnsafeDir) {
				t.Errorf("mode %o: err %v, want ErrUnsafeDir", m, err)
			}
		}
	})

	t.Run("symlinkParent", func(t *testing.T) {
		base := shortDir(t)
		real := filepath.Join(base, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Listen(userOpts(filepath.Join(link, "s.sock"))); !errors.Is(err, ErrUnsafeDir) {
			t.Fatalf("err %v, want ErrUnsafeDir", err)
		}
		if _, err := os.Lstat(filepath.Join(real, "s.sock")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a socket was created through the symlink")
		}
	})

	t.Run("otherOwner", func(t *testing.T) {
		o := userOpts(filepath.Join(shortDir(t), "s.sock"))
		o.Unix.DirOwnerUID = os.Geteuid() + 1
		if _, err := Listen(o); !errors.Is(err, ErrUnsafeDir) {
			t.Fatalf("err %v, want ErrUnsafeDir", err)
		}
	})

	t.Run("missingParent", func(t *testing.T) {
		o := userOpts(filepath.Join(shortDir(t), "sub", "s.sock"))
		if _, err := Listen(o); !errors.Is(err, ErrUnsafeDir) {
			t.Fatalf("err %v, want ErrUnsafeDir", err)
		}
	})

	t.Run("createDir", func(t *testing.T) {
		sub := filepath.Join(shortDir(t), "sub")
		o := userOpts(filepath.Join(sub, "s.sock"))
		o.Unix.CreateDir = true
		o.Unix.DirMode = 0o700
		l, err := Listen(o)
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer l.Close()
		if _, _, mode := statOwner(t, sub); !mode.IsDir() || mode.Perm() != 0o700 {
			t.Fatalf("dir mode %v, want 0700", mode)
		}
	})

	t.Run("staleNeedsLock", func(t *testing.T) {
		addr := filepath.Join(shortDir(t), "s.sock")
		staleSocket(t, addr)
		if _, err := Listen(userOpts(addr)); !errors.Is(err, ErrStaleNeedsLock) {
			t.Fatalf("err %v, want ErrStaleNeedsLock", err)
		}
		if fi, err := os.Lstat(addr); err != nil || fi.Mode()&os.ModeSocket == 0 {
			t.Fatalf("stale socket was touched: %v", err)
		}
	})

	t.Run("staleWithLock", func(t *testing.T) {
		addr := filepath.Join(shortDir(t), "s.sock")
		staleSocket(t, addr)
		o := userOpts(addr)
		o.Unix.HoldsLock = true
		l, err := Listen(o)
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer l.Close()
		go func() {
			if c, err := l.Accept(); err == nil {
				_ = c.Close()
			}
		}()
		if _, err := dialT(t, addr); err != nil {
			t.Fatalf("rebound socket does not accept: %v", err)
		}
	})

	t.Run("liveInUse", func(t *testing.T) {
		addr := filepath.Join(shortDir(t), "s.sock")
		live, err := Listen(userOpts(addr))
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()
		o := userOpts(addr)
		o.Unix.HoldsLock = true
		if _, err := Listen(o); !errors.Is(err, ErrAddressInUse) {
			t.Fatalf("err %v, want ErrAddressInUse", err)
		}
		// The probe connection of the refused Listen is accepted first.
		go func() {
			for {
				c, err := live.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		if _, err := dialT(t, addr); err != nil {
			t.Fatalf("live socket no longer accepts: %v", err)
		}
	})

	t.Run("notASocket", func(t *testing.T) {
		addr := filepath.Join(shortDir(t), "s.sock")
		if err := os.WriteFile(addr, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		o := userOpts(addr)
		o.Unix.HoldsLock = true
		if _, err := Listen(o); err == nil {
			t.Fatal("Listen replaced a regular file")
		}
		if b, err := os.ReadFile(addr); err != nil || string(b) != "x" {
			t.Fatal("regular file was touched")
		}
	})

	t.Run("dirGroup", func(t *testing.T) {
		dir := shortDir(t)
		_, cur, _ := statOwner(t, dir)
		target := otherGroup(cur)
		if target < 0 {
			t.Skip("no second group available to the test user")
		}
		o := userOpts(filepath.Join(dir, "s.sock"))
		o.Unix.DirGID = target
		if _, err := Listen(o); !errors.Is(err, ErrUnsafeDir) {
			t.Fatalf("without CreateDir: err %v, want ErrUnsafeDir", err)
		}
		o.Unix.CreateDir = true
		o.Unix.DirMode = 0o750
		l, err := Listen(o)
		if err != nil {
			t.Fatalf("with CreateDir: %v", err)
		}
		defer l.Close()
		_, gid, mode := statOwner(t, dir)
		if gid != target || mode.Perm() != 0o750 {
			t.Fatalf("dir gid %d mode %v, want %d 0750", gid, mode, target)
		}
	})

	t.Run("existingRootRoot0750", func(t *testing.T) {
		requireRoot(t)
		const adminGID = 4242
		base := shortDir(t)
		if err := os.Chmod(base, 0o755); err != nil {
			t.Fatal(err)
		}
		run := filepath.Join(base, "run")
		if err := os.Mkdir(run, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(run, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(run, 0o750); err != nil {
			t.Fatal(err)
		}
		addr := filepath.Join(run, "ipc.sock")
		l, err := Listen(ListenOptions{Address: addr, Unix: UnixOptions{
			DirOwnerUID: 0, DirGID: adminGID, DirMode: 0o750,
			SocketGID: adminGID, SocketMode: 0o660, CreateDir: true,
		}})
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer l.Close()
		if uid, gid, mode := statOwner(t, run); uid != 0 || gid != adminGID || mode.Perm() != 0o750 {
			t.Fatalf("dir %d:%d %v, want 0:%d 0750", uid, gid, mode, adminGID)
		}
		if uid, gid, mode := statOwner(t, addr); uid != 0 || gid != adminGID || mode.Perm() != 0o660 {
			t.Fatalf("socket %d:%d %v, want 0:%d 0660", uid, gid, mode, adminGID)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		member := &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{adminGID}}
		if code, out := runHelper(t, addr, member); code != 0 {
			t.Fatalf("group member could not connect: exit %d %s", code, out)
		}
		outsider := &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}
		if code, _ := runHelper(t, addr, outsider); code == 0 {
			t.Fatal("a user outside the group connected")
		}
	})
}

// otherGroup returns a gid the test user may chgrp to that differs from cur,
// or -1.
func otherGroup(cur int) int {
	if os.Geteuid() == 0 {
		if cur == 65534 {
			return 4243
		}
		return 65534
	}
	gs, _ := os.Getgroups()
	gs = append([]int{os.Getegid()}, gs...)
	for _, g := range gs {
		if g != cur {
			return g
		}
	}
	return -1
}

func TestUnixConnectNeedsWritePermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket permissions")
	}
	addr := filepath.Join(shortDir(t), "s.sock")
	l, err := Listen(userOpts(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chmod(addr, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := dialT(t, addr); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("dial a mode-0000 socket: err %v, want permission denied", err)
	}
}

func TestUnixAncestorPolicy(t *testing.T) {
	setup := func(t *testing.T, midMode os.FileMode) (string, string) {
		t.Helper()
		base := shortDir(t)
		mid := filepath.Join(base, "m")
		if err := os.Mkdir(mid, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(mid, midMode); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(mid, "d")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		return base, filepath.Join(dir, "s.sock")
	}

	t.Run("worldWritableAncestorRefused", func(t *testing.T) {
		_, addr := setup(t, 0o777)
		if l, err := Listen(userOpts(addr)); !errors.Is(err, ErrUnsafeDir) {
			if l != nil {
				_ = l.Close()
			}
			t.Fatalf("Listen under a world-writable ancestor: %v, want ErrUnsafeDir", err)
		}
	})
	t.Run("stickyAncestorAllowed", func(t *testing.T) {
		_, addr := setup(t, 0o777|os.ModeSticky)
		l, err := Listen(userOpts(addr))
		if err != nil {
			t.Fatalf("Listen under a sticky ancestor: %v", err)
		}
		_ = l.Close()
	})
	t.Run("symlinkedAncestorChecksTheTarget", func(t *testing.T) {
		base, _ := setup(t, 0o777)
		link := filepath.Join(base, "l")
		if err := os.Symlink(filepath.Join(base, "m"), link); err != nil {
			t.Fatal(err)
		}
		// The link is safe, the directory it points at is world-writable.
		if l, err := Listen(userOpts(filepath.Join(link, "d", "s.sock"))); !errors.Is(err, ErrUnsafeDir) {
			if l != nil {
				_ = l.Close()
			}
			t.Fatalf("Listen through a link to a world-writable ancestor: %v, want ErrUnsafeDir", err)
		}
	})
	t.Run("symlinkedSafeAncestorAllowed", func(t *testing.T) {
		base, _ := setup(t, 0o700)
		link := filepath.Join(base, "l")
		if err := os.Symlink(filepath.Join(base, "m"), link); err != nil {
			t.Fatal(err)
		}
		l, err := Listen(userOpts(filepath.Join(link, "d", "s.sock")))
		if err != nil {
			t.Fatalf("Listen through a link to a safe ancestor: %v", err)
		}
		_ = l.Close()
	})
}
