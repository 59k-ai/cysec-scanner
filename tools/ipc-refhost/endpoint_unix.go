// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/59k-ai/cysec-scanner/ipc"
)

// acquireLock takes an exclusive advisory lock on "<address>.lock" next to
// the socket. Holding it is what allows Listen to replace a stale socket
// file: only the lock holder can be sure no live instance owns the path.
func acquireLock(address string) (release func(), err error) {
	f, err := os.OpenFile(address+".lock", os.O_CREATE|os.O_RDWR, 0o600)
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

// listenOptions admits the current user only: the parent directory must be
// owned by us and closed to group and world, and the socket is mode 0600.
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
