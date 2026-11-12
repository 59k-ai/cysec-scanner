// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireLockChecksTheDirectoryFirst(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "rhl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}

	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireLock(filepath.Join(open, "r.sock")); err == nil {
		release()
		t.Fatal("a 0755 directory was accepted")
	}
	if _, err := os.Lstat(filepath.Join(open, "r.sock.lock")); !os.IsNotExist(err) {
		t.Fatalf("the lock file was created before the directory check: %v", err)
	}

	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireLock(filepath.Join(link, "r.sock")); err == nil {
		release()
		t.Fatal("a symlinked directory was accepted")
	}

	// A planted symlink at the lock path is not followed.
	target := filepath.Join(base, "target")
	if err := os.Symlink(target, filepath.Join(private, "r.sock.lock")); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireLock(filepath.Join(private, "r.sock")); err == nil {
		release()
		t.Fatal("a symlinked lock file was followed")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("the symlink target was created: %v", err)
	}
	_ = os.Remove(filepath.Join(private, "r.sock.lock"))

	release, err := acquireLock(filepath.Join(private, "r.sock"))
	if err != nil {
		t.Fatalf("a private directory was refused: %v", err)
	}
	release()
}
