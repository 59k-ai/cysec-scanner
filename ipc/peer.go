// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import "net"

// Peer is the operating-system identity of the process on the other end of a
// local connection, as read by the kernel, not as claimed by the peer.
//
// On Unix, UID, GID and Groups come from the socket peer credentials and SID
// is empty. On Windows, UID and GID are -1 and SID names the token user.
// Admin is the host's verdict on whether the peer is a privileged principal.
type Peer struct {
	UID    int
	GID    int
	Groups []int
	PID    int
	SID    string
	User   string
	Admin  bool
}

// LogAttrs returns the slog key/value pairs that identify a peer in audit
// lines: uid, pid and sid only. Group lists and user names stay out of logs.
func (p Peer) LogAttrs() []any {
	return []any{"uid", p.UID, "pid", p.PID, "sid", p.SID}
}

// Authorizer decides whether a peer may open a session. A non-nil error
// refuses the session; the error text is logged by class only.
type Authorizer interface {
	Authorize(Peer) error
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(Peer) error

// Authorize calls f.
func (f AuthorizerFunc) Authorize(p Peer) error { return f(p) }

// IdentifyFunc reads the peer identity of an accepted connection. The server
// calls it after the hello line has been read, because on Windows the client
// identity is taken from the last message read on the pipe.
type IdentifyFunc func(conn net.Conn) (Peer, error)
