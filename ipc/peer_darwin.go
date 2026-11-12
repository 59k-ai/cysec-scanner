// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// peer_darwin.go reads the peer of an AF_UNIX connection from the kernel:
// LOCAL_PEERCRED gives uid and groups, LOCAL_PEERPID the pid for audit.
//
// struct xucred carries at most 16 groups. When the list is full and the
// admin group is not in it, membership may simply have been cut off, so the
// admin check asks the directory service through dsmemberutil (absolute
// path, bounded time, exact output match).

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	dsmemberutilPath     = "/usr/bin/dsmemberutil"
	dsMemberYes          = "user is a member of the group"
	dsMemberTimeout      = 2 * time.Second
	xucredMaxGroups  int = len(unix.Xucred{}.Groups)
)

// dsMemberCheck runs dsmemberutil; tests replace it.
var dsMemberCheck = func(ctx context.Context, uid, gid int) (string, error) {
	out, err := exec.CommandContext(ctx, dsmemberutilPath, "checkmembership",
		"-u", strconv.Itoa(uid), "-g", strconv.Itoa(gid)).Output()
	return string(out), err
}

func init() { adminGroupFallback = darwinGroupFallback }

// darwinGroupFallback is consulted only when the peer's group list is
// full, i.e. possibly truncated by xucred.
func darwinGroupFallback(p Peer, gid int) bool {
	if len(p.Groups) < xucredMaxGroups {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), dsMemberTimeout)
	defer cancel()
	out, err := dsMemberCheck(ctx, p.UID, gid)
	return err == nil && strings.TrimSpace(out) == dsMemberYes
}

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
		x          *unix.Xucred
		pid        int
		xerr, perr error
	)
	if err := raw.Control(func(fd uintptr) {
		x, xerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, perr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return p, err
	}
	if xerr != nil {
		return p, fmt.Errorf("ipc: LOCAL_PEERCRED: %w", xerr)
	}
	if perr != nil {
		return p, fmt.Errorf("ipc: LOCAL_PEERPID: %w", perr)
	}
	n := min(max(int(x.Ngroups), 0), len(x.Groups))
	groups := make([]int, 0, n)
	for _, g := range x.Groups[:n] {
		groups = append(groups, int(g))
	}
	p = Peer{UID: int(x.Uid), GID: -1, Groups: groups, PID: pid}
	if n > 0 {
		// cr_groups[0] is the effective gid.
		p.GID = groups[0]
	}
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.User = u.Username
	}
	return p, nil
}
