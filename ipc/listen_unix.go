// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ipc

// listen_unix.go is the only place this package binds an AF_UNIX socket.
//
// Order matters. The parent directory is checked first (Lstat, so a symlink
// is refused rather than followed; owner, group and no group or world write
// bit), so nobody but its owner can create or swap entries in it. Only then
// is an existing socket file considered, and it is replaced only when the
// caller holds its single-instance lock and a probe dial finds nothing
// listening. The socket is bound inside that directory and its group and
// mode are set right after bind: the short window in which the socket has
// the umask-derived mode is not reachable, because only the directory's
// owner and group can traverse into it.
//
// Linux abstract sockets ("@name") are refused: socket permissions have no
// meaning there, so anyone could connect or squat.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// maxUnixPath is the longest socket path accepted. macOS sun_path holds 104
// bytes including the terminating NUL (Linux 108); one limit keeps the
// address portable.
const maxUnixPath = 103

// staleProbeTimeout bounds the dial that decides whether an existing socket
// is live.
const staleProbeTimeout = 200 * time.Millisecond

type unixListener struct {
	*net.UnixListener
}

func (l unixListener) Identify() IdentifyFunc { return identifyPeer }

func listen(o ListenOptions) (Listener, error) {
	u := o.Unix
	if u.DirMode == 0 {
		u.DirMode = DefaultDirMode
	}
	if u.SocketMode == 0 {
		u.SocketMode = DefaultSocketMode
	}
	addr := o.Address
	if err := validUnixAddress(addr); err != nil {
		return nil, err
	}
	dir := filepath.Dir(addr)
	if err := prepareDir(dir, u); err != nil {
		return nil, err
	}
	if err := clearStale(addr, u.HoldsLock); err != nil {
		return nil, err
	}

	ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("%w: %s", ErrAddressInUse, addr)
		}
		return nil, err
	}
	ul.SetUnlinkOnClose(true)
	if u.SocketGID >= 0 {
		// Root keeps ownership and hands the group to the admin group; a
		// non-root host can only pick one of its own groups and fails
		// closed when it cannot.
		if err := os.Lchown(addr, -1, u.SocketGID); err != nil {
			_ = ul.Close()
			return nil, fmt.Errorf("ipc: socket group: %w", err)
		}
	}
	if err := os.Chmod(addr, u.SocketMode.Perm()); err != nil {
		_ = ul.Close()
		return nil, fmt.Errorf("ipc: socket mode: %w", err)
	}
	return unixListener{ul}, nil
}

func validUnixAddress(addr string) error {
	switch {
	case addr == "", strings.HasPrefix(addr, "@"), !filepath.IsAbs(addr):
		return fmt.Errorf("%w: socket path must be absolute", ErrInvalidAddress)
	case strings.IndexByte(addr, 0) >= 0:
		return fmt.Errorf("%w: NUL byte in socket path", ErrInvalidAddress)
	case len(addr) > maxUnixPath:
		return fmt.Errorf("%w: socket path longer than %d bytes", ErrInvalidAddress, maxUnixPath)
	case filepath.Clean(addr) != addr:
		return fmt.Errorf("%w: socket path is not clean", ErrInvalidAddress)
	}
	return nil
}

// prepareDir creates (when allowed) and verifies the socket's parent.
func prepareDir(dir string, u UnixOptions) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if !u.CreateDir {
			return fmt.Errorf("%w: %s does not exist", ErrUnsafeDir, dir)
		}
		if err := os.Mkdir(dir, u.DirMode.Perm()); err != nil {
			return fmt.Errorf("ipc: create socket directory: %w", err)
		}
		if err := os.Lchown(dir, u.DirOwnerUID, u.DirGID); err != nil {
			return fmt.Errorf("ipc: socket directory owner: %w", err)
		}
	} else if err != nil {
		return err
	}

	if !u.CreateDir {
		return checkDir(dir, u, false)
	}
	// The group is not checked yet: normalising it is the point of
	// CreateDir. Owner, type and write bits must already be safe.
	pre := u
	pre.DirGID = -1
	if err := checkDir(dir, pre, false); err != nil {
		return err
	}
	// Normalise an existing directory (systemd creates RuntimeDirectory as
	// root:root), so the admin group can traverse it. The pre-check above
	// already proved nobody else could have planted entries in it.
	if err := os.Lchown(dir, u.DirOwnerUID, u.DirGID); err != nil {
		return fmt.Errorf("ipc: socket directory owner: %w", err)
	}
	if err := os.Chmod(dir, u.DirMode.Perm()); err != nil {
		return fmt.Errorf("ipc: socket directory mode: %w", err)
	}
	return checkDir(dir, u, true)
}

// checkDir verifies dir with Lstat. exact also requires mode == DirMode.
func checkDir(dir string, u UnixOptions, exact bool) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a plain directory", ErrUnsafeDir, dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s has no owner information", ErrUnsafeDir, dir)
	}
	if int(st.Uid) != u.DirOwnerUID {
		return fmt.Errorf("%w: %s owner %d, want %d", ErrUnsafeDir, dir, st.Uid, u.DirOwnerUID)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is group- or world-writable", ErrUnsafeDir, dir)
	}
	if u.DirGID >= 0 && int(st.Gid) != u.DirGID {
		return fmt.Errorf("%w: %s group %d, want %d", ErrUnsafeDir, dir, st.Gid, u.DirGID)
	}
	if exact && fi.Mode().Perm() != u.DirMode.Perm() {
		return fmt.Errorf("%w: %s mode %o, want %o", ErrUnsafeDir, dir, fi.Mode().Perm(), u.DirMode.Perm())
	}
	return nil
}

// clearStale handles an existing entry at the socket path.
func clearStale(addr string, holdsLock bool) error {
	fi, err := os.Lstat(addr)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%w: %s exists and is not a socket", ErrAddressInUse, addr)
	}
	if !holdsLock {
		return fmt.Errorf("%w: %s", ErrStaleNeedsLock, addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), staleProbeTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", addr)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("%w: %s has a live listener", ErrAddressInUse, addr)
	}
	// Only a refused connection proves nothing is listening; a timeout means
	// a busy live listener and anything else is not ours to judge.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: probe %s: %v", ErrAddressInUse, addr, err)
	}
	if err := os.Remove(addr); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("ipc: remove stale socket: %w", err)
	}
	return nil
}
