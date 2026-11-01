// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

// hwAddr parses s as a hardware address for an interface fixture.
func hwAddr(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	hw, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return hw
}

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

// TestLocalInterfaceMACsFrom proves the own-address -> MAC map: IPv4 only, MAC
// canonicalised to lower case, loopback and interfaces without a usable unicast
// 48-bit address (tunnel, macOS placeholder, group, all-zero, IPoIB) dropped,
// and a shared IP resolved to the lowest interface name whatever the input
// order.
func TestLocalInterfaceMACsFrom(t *testing.T) {
	t.Parallel()
	views := []ifaceView{
		{name: "wlan0", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "3c:22:fb:12:34:56"),
			addrs: []*net.IPNet{ifAddr(t, "192.168.1.30/24"), ifAddr(t, "fe80::1/64")}},
		{name: "eth0", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "00:1A:2B:3C:4D:5E"),
			addrs: []*net.IPNet{ifAddr(t, "192.0.2.5/24"), ifAddr(t, "192.0.2.6/24")}},
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []*net.IPNet{ifAddr(t, "127.0.0.1/8")}},
		{name: "tun0", flags: net.FlagUp | net.FlagPointToPoint, addrs: []*net.IPNet{ifAddr(t, "10.8.0.2/24")}},
		{name: "en0", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "02:00:00:00:00:00"),
			addrs: []*net.IPNet{ifAddr(t, "198.51.100.7/24")}},
		{name: "grp0", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "01:00:5e:00:00:01"),
			addrs: []*net.IPNet{ifAddr(t, "198.51.100.8/24")}},
		{name: "zero0", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "00:00:00:00:00:00"),
			addrs: []*net.IPNet{ifAddr(t, "198.51.100.9/24")}},
		{name: "ib0", flags: net.FlagUp | net.FlagBroadcast,
			hw:    hwAddr(t, "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01"),
			addrs: []*net.IPNet{ifAddr(t, "198.51.100.10/24")}},
		{name: "br1", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "aa:bb:cc:00:00:02"),
			addrs: []*net.IPNet{ifAddr(t, "203.0.113.9/24")}},
		{name: "br0", flags: net.FlagUp | net.FlagBroadcast, hw: hwAddr(t, "aa:bb:cc:00:00:01"),
			addrs: []*net.IPNet{ifAddr(t, "203.0.113.9/24")}},
	}
	got := localInterfaceMACsFrom(views)
	want := map[string]string{
		"192.168.1.30": "3c:22:fb:12:34:56",
		"192.0.2.5":    "00:1a:2b:3c:4d:5e",
		"192.0.2.6":    "00:1a:2b:3c:4d:5e",
		"203.0.113.9":  "aa:bb:cc:00:00:01",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("localInterfaceMACsFrom = %v, want %v", got, want)
	}
	if empty := localInterfaceMACsFrom(nil); empty == nil || len(empty) != 0 {
		t.Fatalf("localInterfaceMACsFrom(nil) = %#v, want a non-nil empty map", empty)
	}
}

// TestLocalInterfaceMACsHost smoke-tests the host path: a non-nil map whose keys
// are non-loopback IPv4 addresses and whose values are canonical MACs.
func TestLocalInterfaceMACsHost(t *testing.T) {
	t.Parallel()
	got := LocalInterfaceMACs()
	if got == nil {
		t.Fatal("LocalInterfaceMACs returned nil, want a non-nil map")
	}
	for ip, mac := range got {
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			t.Errorf("key %q is not an IPv4 address", ip)
			continue
		}
		if a.IsLoopback() {
			t.Errorf("key %q is a loopback address", ip)
		}
		if norm, ok := normalizeMAC(mac); !ok || norm != mac {
			t.Errorf("value %q for %s is not a canonical MAC (normalizeMAC = %q, %v)", mac, ip, norm, ok)
		}
	}
}
