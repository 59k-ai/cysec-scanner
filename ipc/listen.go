// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// listen.go declares the platform-neutral half of the local endpoint: the
// options, the Listener contract and the errors. The endpoint is always a
// filesystem object that the kernel guards with an access check — an AF_UNIX
// socket inside a verified directory on Linux and macOS, a named pipe with an
// explicit DACL on Windows. There is deliberately no TCP code path: a
// loopback port is reachable by every local user and by anything that can
// forward to it, so it cannot carry a privileged control channel.

import (
	"errors"
	"net"
	"os"
)

// Default modes and sizes applied when the corresponding option is zero.
const (
	DefaultDirMode        os.FileMode = 0o750
	DefaultSocketMode     os.FileMode = 0o660
	DefaultPipeBufferSize int32       = 64 << 10
)

var (
	// ErrUnsafeDir means the socket's parent directory is missing, is a
	// symlink or not a directory, has the wrong owner or group, or is
	// writable by group or world. Another user could then swap or pre-create
	// the socket path, so the listener refuses to bind there.
	ErrUnsafeDir = errors.New("ipc: unsafe socket directory")
	// ErrStaleNeedsLock means a socket file already exists and the caller
	// did not declare that it holds its single-instance lock. Removing it
	// without that lock could unlink a live peer's endpoint.
	ErrStaleNeedsLock = errors.New("ipc: existing socket needs the instance lock to replace")
	// ErrAddressInUse means a live endpoint already answers on the address,
	// or (Windows) another process owns the pipe name.
	ErrAddressInUse = errors.New("ipc: address in use")
	// ErrInvalidAddress means the address is not an acceptable local
	// endpoint for this platform.
	ErrInvalidAddress = errors.New("ipc: invalid address")
)

// ListenOptions configure Listen. Address is an absolute socket path on Unix
// and a \\.\pipe\ name on Windows; only the block for the running platform
// is read.
//
// On Unix every directory above the socket's parent must be owned by root,
// the caller or UnixOptions.DirOwnerUID and must not be group- or
// world-writable unless it is sticky; Listen refuses the address otherwise
// (ErrUnsafeDir).
type ListenOptions struct {
	Address string
	Unix    UnixOptions
	Pipe    PipeOptions
}

// UnixOptions is the filesystem policy for an AF_UNIX endpoint.
//
// DirOwnerUID is the uid that must own the parent directory. DirGID and
// SocketGID are the groups the directory and the socket must carry; a
// negative value disables that group check or change (0 is the root group,
// not "unset"). DirMode and SocketMode default to 0750 and 0660.
//
// CreateDir lets Listen create a missing parent and normalise an existing
// one to DirOwnerUID:DirGID and DirMode exactly. HoldsLock declares that the
// caller holds its single-instance lock, which is the only condition under
// which a stale socket file is replaced.
type UnixOptions struct {
	DirOwnerUID int
	DirGID      int
	DirMode     os.FileMode
	SocketMode  os.FileMode
	SocketGID   int
	CreateDir   bool
	HoldsLock   bool
}

// PipeOptions is the policy for a Windows named pipe. SDDL is required:
// there is no default, because the default named-pipe DACL grants read
// access to Everyone. BufferSize defaults to 64 KiB.
type PipeOptions struct {
	SDDL       string
	BufferSize int32
}

// Listener is a local endpoint that also knows how to read the kernel
// identity of the peers it accepts. Identify is meant for
// ServerOptions.Identify.
type Listener interface {
	net.Listener
	Identify() IdentifyFunc
}

// Listen creates the local endpoint described by o.
func Listen(o ListenOptions) (Listener, error) {
	return listen(o)
}
