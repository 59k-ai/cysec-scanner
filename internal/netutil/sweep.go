// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
)

const (
	// defaultConcurrency bounds in-flight probes so a sweep never floods a
	// production network (DoS mitigation, V12 / T-3-02).
	defaultConcurrency = 32
	// defaultHostTimeout bounds each per-host probe.
	defaultHostTimeout = 1 * time.Second
	// maxSweepHosts caps the total host count enumerated from the scope so a
	// pathologically wide prefix cannot exhaust memory. Typical auto-detected
	// LANs are a /24; an explicit wider scope is bounded here defensively.
	maxSweepHosts = 65536
)

// SweepResult is one live host found by the sweep: its IP plus a best-effort
// reply TTL (0 when unknown) carried forward as a low-confidence OS hint.
type SweepResult struct {
	IP  string
	TTL int
}

// Sweep probes every IPv4 host in the given CIDRs (or bare IPs) with a bounded
// worker pool, honoring ctx cancellation and a per-host timeout, and returns the
// live hosts in deterministic (sorted) order.
//
// ping is the injectable liveness seam; pass nil to use the capability-selected
// default pinger. When neither ICMP path is available (per caps) and no explicit
// pinger is injected, Sweep yields zero live hosts rather than erroring — the
// unprivileged default must always degrade gracefully (ENG-06).
func Sweep(ctx context.Context, cidrs []string, caps capabilities.Capabilities, ping PingFunc) []SweepResult {
	if ping == nil {
		ping = defaultPinger(caps)
	}
	if ping == nil {
		return nil
	}
	hosts := enumerateHosts(cidrs)
	if len(hosts) == 0 {
		return nil
	}

	sem := make(chan struct{}, defaultConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var live []SweepResult

	for _, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			ok, ttl := ping(ctx, ip, defaultHostTimeout)
			if ok {
				mu.Lock()
				live = append(live, SweepResult{IP: ip, TTL: ttl})
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	sort.Slice(live, func(i, j int) bool { return live[i].IP < live[j].IP })
	return live
}

// defaultPinger selects the live sweep path from the detected capabilities.
// When neither the unprivileged UDP-ICMP socket nor a system `ping` binary is
// available, there is no viable liveness probe, so it returns nil and the sweep
// yields zero hosts rather than erroring — the unprivileged default degrades
// gracefully (ENG-06).
func defaultPinger(caps capabilities.Capabilities) PingFunc {
	if !caps.UnprivilegedICMP && !caps.SystemPing {
		return nil
	}
	return pingHost
}

// enumerateHosts expands the scope tokens into probe-target IPs. For prefixes
// shorter than /31 the network and broadcast addresses are skipped (never
// probe a broadcast). The total is capped at maxSweepHosts.
func enumerateHosts(cidrs []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, token := range cidrs {
		prefix, ok := parsePrefixOrAddr(token)
		if !ok {
			continue
		}
		for _, ip := range hostsInPrefix(prefix) {
			if len(out) >= maxSweepHosts {
				return out
			}
			if _, dup := seen[ip]; dup {
				continue
			}
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	return out
}

// hostsInPrefix lists the probe-target addresses in an IPv4 prefix, skipping the
// network and broadcast addresses for prefixes shorter than /31.
func hostsInPrefix(prefix netip.Prefix) []string {
	bits := prefix.Bits()
	network := prefix.Addr()
	var out []string
	for addr := network; prefix.Contains(addr); addr = addr.Next() {
		if bits < 31 {
			if addr == network {
				continue // network address
			}
			if !prefix.Contains(addr.Next()) {
				continue // broadcast address (last in range)
			}
		}
		out = append(out, addr.String())
		if len(out) >= maxSweepHosts {
			break
		}
	}
	return out
}
