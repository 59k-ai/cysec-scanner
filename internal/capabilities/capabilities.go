// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package capabilities records, once at startup, what the host runtime permits
// the unprivileged scan engine to do.
//
// ENG-06: Detect() runs exactly once and returns an immutable value struct;
// stages receive it by value and cannot mutate the detected state. The
// unprivileged path is the shipped default and must always produce a complete,
// valid payload even when every capability is absent — capability absence
// degrades the result (fewer hosts, null MAC/vendor) but never crashes.
package capabilities

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/icmp"
)

// Capabilities is an immutable snapshot of the runtime facts detected at
// startup. It holds only value (bool) fields, so a copy shares no mutable state
// with the original: passing it by value to a stage can never alter the detected
// truth (the ENG-06 immutability contract).
type Capabilities struct {
	// UnprivilegedICMP is true when an unprivileged UDP-ICMP ("ping") datagram
	// socket is usable (governed on Linux by net.ipv4.ping_group_range).
	UnprivilegedICMP bool
	// SystemPing is true when a `ping` binary is resolvable on PATH — the
	// mandatory fallback when UnprivilegedICMP is refused.
	SystemPing bool
	// ARPCache is true when the kernel ARP/neighbour cache is readable, the
	// source of L2 (MAC) evidence harvested after a sweep.
	ARPCache bool
}

// Detect probes the runtime facts once and returns them by value. It is called
// exactly once at engine startup; the result is threaded by value and never
// re-detected mid-run (ENG-06).
func Detect() Capabilities {
	return Capabilities{
		UnprivilegedICMP: detectUnprivilegedICMP(),
		SystemPing:       detectSystemPing(),
		ARPCache:         detectARPCache(),
	}
}

// detectUnprivilegedICMP best-effort checks whether an unprivileged UDP-ICMP
// datagram socket can be opened for IPv4. On stock Linux this is refused unless
// the process GID falls within net.ipv4.ping_group_range, so a refusal is the
// common case and simply steers the sweep onto the system-ping fallback.
func detectUnprivilegedICMP() bool {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// detectSystemPing reports whether a `ping` binary is resolvable on PATH.
func detectSystemPing() bool {
	_, err := exec.LookPath("ping")
	return err == nil
}

// detectARPCache reports whether the kernel ARP/neighbour cache is readable on
// this platform — the source of L2 MAC evidence harvested after a sweep. On
// Linux that is /proc/net/arp; elsewhere it is the `arp` binary used to parse
// `arp -an` / `arp -a`. A negative result degrades MAC/vendor to "not observed"
// (null), never a crash.
//
// On macOS the binary existing is not enough: macOS 27 hides the IPv4 neighbour
// cache from processes without root or the network topology-observation
// entitlement, and `arp -an` then prints nothing. Local Network permission does
// not lift this. darwin therefore reports the cache readable only when it
// actually lists an entry.
func detectARPCache() bool {
	switch runtime.GOOS {
	case "linux":
		f, err := os.Open("/proc/net/arp")
		if err != nil {
			return false
		}
		_ = f.Close()
		return true
	case "darwin":
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "arp", "-an").Output()
		if err != nil {
			return false
		}
		return arpOutputListsEntries(string(out))
	case "windows", "freebsd", "openbsd", "netbsd":
		_, err := exec.LookPath("arp")
		return err == nil
	default:
		return false
	}
}

// arpOutputListsEntries reports whether BSD `arp -an` output lists at least one
// cache entry. A readable cache always holds the interface's own permanent entry
// even when every neighbour is still "(incomplete)", so an entry line of any kind
// proves the cache is visible; empty output is the hidden-cache signature.
func arpOutputListsEntries(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " at ") {
			return true
		}
	}
	return false
}
