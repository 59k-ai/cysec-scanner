// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"net"
	"reflect"
	"testing"
)

// TestLocalLANInterfacesFrom proves the interface-aware listing keeps the iface
// name per network, applies the same exclusion rules as localLANNetworksFrom
// (overlay tun0 and loopback dropped) and sorts by CIDR (SGUI-02).
func TestLocalLANInterfacesFrom(t *testing.T) {
	t.Parallel()
	views := []ifaceView{
		{name: "wlan0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "198.51.100.9/24")}},
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []*net.IPNet{ifAddr(t, "127.0.0.1/8")}},
		{name: "tun0", flags: net.FlagUp, addrs: []*net.IPNet{ifAddr(t, "203.0.113.2/24")}},
		{name: "eth0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "192.0.2.5/24")}},
	}
	got := localLANInterfacesFrom(views)
	want := []LANNetwork{
		{Interface: "eth0", CIDR: "192.0.2.0/24"},
		{Interface: "wlan0", CIDR: "198.51.100.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("localLANInterfacesFrom = %v, want %v", got, want)
	}
	if nets := localLANNetworksFrom(views); !reflect.DeepEqual(nets, []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("localLANNetworksFrom projection = %v", nets)
	}
}

// TestLocalLANInterfacesSameCIDRTwoIfaces proves two interfaces on the same
// network both appear (sorted by interface) while the CIDR projection
// de-duplicates them, keeping LocalLANNetworks' legacy output unchanged.
func TestLocalLANInterfacesSameCIDRTwoIfaces(t *testing.T) {
	t.Parallel()
	views := []ifaceView{
		{name: "eth1", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "192.0.2.7/24")}},
		{name: "eth0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "192.0.2.5/24"), ifAddr(t, "192.0.2.6/24")}},
	}
	got := localLANInterfacesFrom(views)
	want := []LANNetwork{
		{Interface: "eth0", CIDR: "192.0.2.0/24"},
		{Interface: "eth1", CIDR: "192.0.2.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("localLANInterfacesFrom = %v, want %v", got, want)
	}
	if nets := localLANNetworksFrom(views); !reflect.DeepEqual(nets, []string{"192.0.2.0/24"}) {
		t.Fatalf("localLANNetworksFrom projection = %v", nets)
	}
}

// TestLocalLANInterfacesHost smoke-tests the host path: it never returns an
// entry with an empty CIDR.
func TestLocalLANInterfacesHost(t *testing.T) {
	t.Parallel()
	for _, n := range LocalLANInterfaces() {
		if n.CIDR == "" {
			t.Fatalf("empty CIDR in %v", n)
		}
	}
}
