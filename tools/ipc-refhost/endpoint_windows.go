// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "github.com/59k-ai/cysec-scanner/ipc"

// acquireLock is a no-op on Windows: the pipe listener refuses to start when
// another process already owns the name, so no stale endpoint can exist.
func acquireLock(string) (func(), error) { return func() {}, nil }

// listenOptions admits the current user (and LocalSystem) only.
func listenOptions(address string) (ipc.ListenOptions, error) {
	sid, err := ipc.CurrentUserSID()
	if err != nil {
		return ipc.ListenOptions{}, err
	}
	return ipc.ListenOptions{Address: address, Pipe: ipc.PipeOptions{SDDL: ipc.SameUserPipeSDDL(sid)}}, nil
}
