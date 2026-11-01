// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package netutil

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// ARPTable returns the kernel ARP cache as an {ip: mac} map on non-Linux hosts
// by parsing `arp -an` (`arp -a` on Windows). Any failure (no arp binary on PATH,
// a non-zero exit, a timeout) yields an empty map rather than an error —
// MAC/vendor then degrades to "not observed" (null), never a crash (Pitfall 6).
//
// macOS 27 hides the IPv4 neighbour cache from processes without root or the
// network topology-observation entitlement: arp then prints nothing and this
// returns an empty map. The capability layer detects that case and reports
// ARPCache=false.
func ARPTable() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "arp", arpCommandArgs(runtime.GOOS)...).Output()
	if err != nil {
		return map[string]string{}
	}
	return parseARPCommand(string(out))
}
