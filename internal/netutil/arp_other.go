//go:build !linux

package netutil

import (
	"context"
	"os/exec"
	"time"
)

// ARPTable returns the kernel ARP cache as an {ip: mac} map on non-Linux hosts
// by parsing `arp -a`. Any failure (no arp binary on PATH, a non-zero exit, a
// timeout) yields an empty map rather than an error — MAC/vendor then degrades
// to "not observed" (null), never a crash (Pitfall 6).
func ARPTable() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "arp", "-a").Output()
	if err != nil {
		return map[string]string{}
	}
	return parseARPCommand(string(out))
}
