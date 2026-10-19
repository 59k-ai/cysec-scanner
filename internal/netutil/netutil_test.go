// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
)

// ifAddr builds a *net.IPNet shaped like an interface address (IP = the host's
// address on the link, Mask = the link prefix), matching what net.Interface.Addrs
// returns.
func ifAddr(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return &net.IPNet{IP: ip, Mask: ipnet.Mask}
}

// TestLocalLANNetworksFrom proves the exclusion rules: a loopback, a down
// interface, a point-to-point tunnel and an overlay bridge are all skipped;
// only the up Ethernet's real /prefix survives (DISC-01).
func TestLocalLANNetworksFrom(t *testing.T) {
	t.Parallel()
	views := []ifaceView{
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []*net.IPNet{ifAddr(t, "127.0.0.1/8")}},
		{name: "eth0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "192.168.1.5/24")}},
		{name: "docker0", flags: net.FlagUp | net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "172.17.0.1/16")}},
		{name: "tun0", flags: net.FlagUp | net.FlagPointToPoint, addrs: []*net.IPNet{ifAddr(t, "10.8.0.2/24")}},
		{name: "eth1", flags: net.FlagBroadcast, addrs: []*net.IPNet{ifAddr(t, "10.0.0.5/24")}}, // down: no FlagUp
	}
	got := localLANNetworksFrom(views)
	want := []string{"192.168.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("localLANNetworksFrom = %v, want %v", got, want)
	}
}

// TestPingFallback proves pro-bing -> system-ping selection: when the pro-bing
// probe reports no reply, pingHost calls the system-ping fallback; when pro-bing
// reports a reply, the fallback is not called (Pattern 2 / Pitfall 1).
func TestPingFallback(t *testing.T) {
	origICMP, origSys := icmpProbe, systemProbe
	defer func() { icmpProbe, systemProbe = origICMP, origSys }()

	// pro-bing fails -> fallback must run.
	icmpProbe = func(context.Context, string, time.Duration) (bool, int) { return false, 0 }
	fallbackCalled := false
	systemProbe = func(context.Context, string, time.Duration) (bool, int) {
		fallbackCalled = true
		return true, 64
	}
	live, ttl := pingHost(context.Background(), "127.0.0.1", time.Second)
	if !fallbackCalled {
		t.Fatal("system-ping fallback not called after pro-bing returned no reply")
	}
	if !live || ttl != 64 {
		t.Fatalf("pingHost (fallback) = (%v, %d), want (true, 64)", live, ttl)
	}

	// pro-bing succeeds -> fallback must NOT run.
	icmpProbe = func(context.Context, string, time.Duration) (bool, int) { return true, 128 }
	systemProbe = func(context.Context, string, time.Duration) (bool, int) {
		t.Fatal("fallback called even though pro-bing reported a reply")
		return false, 0
	}
	live, ttl = pingHost(context.Background(), "127.0.0.1", time.Second)
	if !live || ttl != 128 {
		t.Fatalf("pingHost (primary) = (%v, %d), want (true, 128)", live, ttl)
	}
}

// TestParseReplyTTL proves the low-confidence TTL hint is parsed when present
// and collapses to 0 when absent (Pitfall 7).
func TestParseReplyTTL(t *testing.T) {
	t.Parallel()
	if got := parseReplyTTL("64 bytes from 1.1.1.1: icmp_seq=1 ttl=117 time=5.0 ms"); got != 117 {
		t.Errorf("parseReplyTTL with ttl= line = %d, want 117", got)
	}
	if got := parseReplyTTL("1 packets transmitted, 1 received, 0% packet loss"); got != 0 {
		t.Errorf("parseReplyTTL without ttl= = %d, want 0", got)
	}
}

// TestEnumerateHosts proves host expansion: a /32 is the single host, a /30
// skips its network and broadcast, a bare IP is a /32, and IPv6 scope is ignored
// (IPv4-only sweep, FUT-02).
func TestEnumerateHosts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		cidrs []string
		want  []string
	}{
		{"single /32", []string{"127.0.0.1/32"}, []string{"127.0.0.1"}},
		{"/30 skips net+broadcast", []string{"192.168.1.0/30"}, []string{"192.168.1.1", "192.168.1.2"}},
		{"bare IPv4 is /32", []string{"10.0.0.5"}, []string{"10.0.0.5"}},
		{"IPv6 ignored", []string{"::1/128"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := enumerateHosts(c.cidrs)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("enumerateHosts(%v) = %v, want %v", c.cidrs, got, c.want)
			}
		})
	}
}

// TestSweepInjectedPinger proves the bounded concurrent sweep collects exactly
// the hosts the injected pinger reports live, in deterministic order (exercised
// under -race for the shared accumulator).
func TestSweepInjectedPinger(t *testing.T) {
	t.Parallel()
	ping := func(_ context.Context, ip string, _ time.Duration) (bool, int) {
		if ip == "192.168.1.2" {
			return true, 64
		}
		return false, 0
	}
	got := Sweep(context.Background(), []string{"192.168.1.0/29"}, capabilities.Capabilities{}, ping)
	if len(got) != 1 || got[0].IP != "192.168.1.2" || got[0].TTL != 64 {
		t.Fatalf("Sweep = %+v, want one live 192.168.1.2 ttl 64", got)
	}
}
