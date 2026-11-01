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

// arpCommandOutput runs `arp -an` (`arp -a` on Windows) with a short timeout. It
// is a seam so the darwin source order can be tested without a real cache.
var arpCommandOutput = func() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "arp", arpCommandArgs(runtime.GOOS)...).Output()
}

// arpCommandTable returns the ARP cache as an {ip: mac} map by parsing the arp
// command's output. Any failure (no arp binary on PATH, a non-zero exit, a
// timeout) yields an empty map rather than an error — MAC/vendor then degrades
// to "not observed" (null), never a crash (Pitfall 6).
func arpCommandTable() map[string]string {
	out, err := arpCommandOutput()
	if err != nil {
		return map[string]string{}
	}
	return parseARPCommand(string(out))
}
