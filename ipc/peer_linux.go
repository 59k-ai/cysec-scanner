// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// peer_linux.go reads the peer of an AF_UNIX connection from the kernel.
//
// SO_PEERCRED gives uid, primary gid and pid as of connect(2), but no
// supplementary groups. Those come from SO_PEERGROUPS (Linux 4.13+), read
// with a raw getsockopt: the gid array is binary and contains zero bytes, so
// a string-returning helper would truncate it at the first NUL. Where the
// option is missing, the groups are taken from /proc/<pid>/status, accepted
// only when its effective uid still matches the socket's.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// peerGroupsFn and procStatusFn are swapped by tests.
var (
	peerGroupsFn = rawPeerGroups
	procStatusFn = func(pid int) ([]byte, error) {
		return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	}
)

func identifyPeer(c net.Conn) (Peer, error) {
	p := Peer{UID: -1, GID: -1}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return p, fmt.Errorf("ipc: %T has no socket", c)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return p, err
	}
	var (
		cred       *unix.Ucred
		groups     []int
		cerr, gerr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if cerr == nil {
			groups, gerr = peerGroupsFn(int(fd))
		}
	}); err != nil {
		return p, err
	}
	if cerr != nil {
		return p, fmt.Errorf("ipc: SO_PEERCRED: %w", cerr)
	}
	if errors.Is(gerr, unix.ENOPROTOOPT) {
		var status []byte
		if status, gerr = procStatusFn(int(cred.Pid)); gerr == nil {
			groups, gerr = parseProcGroups(status, int(cred.Uid))
		}
	}
	if gerr != nil {
		// Without the group list the admin rule cannot be decided; fail
		// closed rather than guess.
		return p, fmt.Errorf("ipc: peer groups: %w", gerr)
	}
	if !slices.Contains(groups, int(cred.Gid)) {
		groups = append(groups, int(cred.Gid))
	}
	p = Peer{UID: int(cred.Uid), GID: int(cred.Gid), Groups: groups, PID: int(cred.Pid)}
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.User = u.Username
	}
	return p, nil
}

// rawPeerGroups reads SO_PEERGROUPS, growing the buffer on ERANGE.
func rawPeerGroups(fd int) ([]int, error) {
	buf := make([]uint32, 64)
	for range 4 {
		n := uint32(len(buf) * 4)
		_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
		if e == unix.ERANGE {
			buf = make([]uint32, n/4+1)
			continue
		}
		if e != 0 {
			return nil, e
		}
		out := make([]int, 0, n/4)
		for _, g := range buf[:n/4] {
			out = append(out, int(g))
		}
		return out, nil
	}
	return nil, unix.ERANGE
}

// parseProcGroups extracts Groups: from a /proc/<pid>/status image and
// refuses it unless its effective uid equals uid, which catches a pid that
// was reused by another user's process.
func parseProcGroups(status []byte, uid int) ([]int, error) {
	var (
		groups           []int
		sawUID, sawGroup bool
	)
	for line := range bytes.SplitSeq(status, []byte("\n")) {
		key, val, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		fields := bytes.Fields(val)
		switch string(key) {
		case "Uid":
			if len(fields) < 2 {
				return nil, errors.New("ipc: malformed Uid line")
			}
			euid, err := strconv.Atoi(string(fields[1]))
			if err != nil {
				return nil, errors.New("ipc: malformed Uid line")
			}
			if euid != uid {
				return nil, errors.New("ipc: peer process changed owner")
			}
			sawUID = true
		case "Groups":
			for _, f := range fields {
				g, err := strconv.Atoi(string(f))
				if err != nil {
					return nil, errors.New("ipc: malformed Groups line")
				}
				groups = append(groups, g)
			}
			sawGroup = true
		}
	}
	if !sawUID || !sawGroup {
		return nil, errors.New("ipc: incomplete process status")
	}
	if groups == nil {
		groups = []int{}
	}
	return groups, nil
}
