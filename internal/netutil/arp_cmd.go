// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package netutil

// ARPTable returns the kernel ARP cache as an {ip: mac} map on Windows and the
// BSDs by parsing `arp -an` (`arp -a` on Windows). A failure yields an empty map.
func ARPTable() map[string]string {
	return arpCommandTable()
}
