// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package capabilities

import (
	"bytes"
	"syscall"

	"golang.org/x/net/route"
)

// netRTFlagsPriv is NET_RT_FLAGS_PRIV from the macOS 27 SDK <sys/socket.h>; the
// engine's darwin ARP reader uses the same sysctl.
const netRTFlagsPriv = 10

var (
	zeroMAC        = []byte{0, 0, 0, 0, 0, 0}
	placeholderMAC = []byte{0x02, 0, 0, 0, 0, 0} // macOS 27 redaction placeholder
)

// sysctlARPReadable reports whether the in-process neighbour dump yields at
// least one usable MAC — true for root or an engine signed with the network
// topology-observation entitlement, false on a hidden cache.
func sysctlARPReadable() bool {
	b, err := route.FetchRIB(syscall.AF_INET, route.RIBType(netRTFlagsPriv), syscall.RTF_LLINFO)
	if err != nil {
		return false
	}
	return llinfoListsUsableMAC(b)
}

// llinfoListsUsableMAC reports whether a routing-sysctl dump holds an IPv4
// RTF_LLINFO entry with a 6-byte unicast MAC that is neither all-zero nor the
// 02:00:00:00:00:00 redaction placeholder.
func llinfoListsUsableMAC(b []byte) bool {
	msgs, _ := route.ParseRIB(route.RIBTypeRoute, b)
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_LLINFO == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		if _, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr); !ok {
			continue
		}
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || len(gw.Addr) != 6 || gw.Addr[0]&0x01 != 0 {
			continue
		}
		if !bytes.Equal(gw.Addr, zeroMAC) && !bytes.Equal(gw.Addr, placeholderMAC) {
			return true
		}
	}
	return false
}
