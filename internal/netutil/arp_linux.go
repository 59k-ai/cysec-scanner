// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netutil

import "os"

// ARPTable returns the kernel ARP cache as an {ip: mac} map on Linux by reading
// /proc/net/arp. A read failure yields an empty map (the capability layer records
// ARPCache=false in that case); discovery then treats an absent entry as "not
// observed", never a crash (Pitfall 6).
func ARPTable() map[string]string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return map[string]string{}
	}
	return parseProcNetARP(string(data))
}
