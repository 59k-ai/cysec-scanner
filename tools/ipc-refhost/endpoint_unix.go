// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/59k-ai/cysec-scanner/ipc"
)

// acquireLock takes an exclusive advisory lock on "<address>.lock" next to
// the socket. Holding it is what allows Listen to replace a stale socket
// file: only the lock holder can be sure no live instance owns the path.
//
// The lock file is created before Listen checks the directory, so the
// directory is checked here first: a plain directory (not a symlink) owned
// by us and closed to group and world. The lock file itself is opened
// without following a symlink.
func acquireLock(address string) (release func(), err error) {
	if err := checkPrivateDir(filepath.Dir(address)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(address+".lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another instance holds %s.lock: %w", address, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// checkPrivateDir requires dir to be a plain directory owned by the current
// user with no group or world permission bits.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is open to group or world (mode %o), want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// listenOptions admits the current user only: the parent directory must be
// owned by us, the socket is mode 0600. Listen's own check (CreateDir false)
// only refuses group and world write; acquireLock, which runs first, is
// what keeps the directory closed to group and world entirely.
func listenOptions(address string) (ipc.ListenOptions, error) {
	return ipc.ListenOptions{Address: address, Unix: ipc.UnixOptions{
		DirOwnerUID: os.Getuid(),
		DirGID:      -1,
		DirMode:     0o700,
		SocketMode:  0o600,
		SocketGID:   -1,
		HoldsLock:   true,
	}}, nil
}
