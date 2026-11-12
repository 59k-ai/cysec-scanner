// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !linux && !darwin

package ipc

import (
	"errors"
	"net"
	"runtime"
)

// identifyPeer fails closed on Unix systems whose peer-credential call this
// package does not implement, so no session is ever authorised there.
func identifyPeer(net.Conn) (Peer, error) {
	return Peer{UID: -1, GID: -1}, errors.New("ipc: peer credentials not supported on " + runtime.GOOS)
}
