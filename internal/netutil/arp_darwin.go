// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package netutil

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// netRTFlagsPriv is NET_RT_FLAGS_PRIV from the macOS 27 SDK <sys/socket.h>:
// "Allows read access non-local host's MAC address if the process has neighbor
// cache entitlement". Older kernels reject it, which falls back to arp -an.
const netRTFlagsPriv = 10

// fetchLLInfo dumps the AF_INET RTF_LLINFO (neighbour) routes in-process. It is
// a seam for tests.
var fetchLLInfo = func() ([]byte, error) {
	return route.FetchRIB(syscall.AF_INET, route.RIBType(netRTFlagsPriv), syscall.RTF_LLINFO)
}

// ARPTable returns the kernel ARP cache as an {ip: mac} map on macOS.
//
// macOS 27 hides the IPv4 neighbour cache from processes without root or the
// com.apple.developer.networking.topology-observation entitlement. The
// entitlement belongs to the signed engine binary and is not inherited by a
// spawned /usr/sbin/arp, so the cache is read in-process via sysctl
// NET_RT_FLAGS_PRIV first. An empty or failed read falls back to `arp -an`
// (root, and macOS releases before 27). Both empty means the cache is hidden.
func ARPTable() map[string]string {
	if b, err := fetchLLInfo(); err == nil {
		if m := parseRouteARP(b); len(m) > 0 {
			return m
		}
	}
	return arpCommandTable()
}

// parseRouteARP parses a routing-sysctl dump into an {ip: mac} map, keeping
// IPv4 RTF_LLINFO entries whose gateway is a 6-byte link-layer address that
// passes normalizeMAC (no incomplete, all-zero, group or redaction-placeholder
// address). A malformed dump yields an empty map, never a panic.
func parseRouteARP(b []byte) map[string]string {
	out := map[string]string{}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil && len(msgs) == 0 {
		return out
	}
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_LLINFO == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || len(gw.Addr) != 6 {
			continue
		}
		mac, ok := normalizeMAC(net.HardwareAddr(gw.Addr).String())
		if !ok {
			continue
		}
		out[net.IP(dst.IP[:]).String()] = mac
	}
	return out
}
