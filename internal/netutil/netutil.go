// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package netutil holds the low-level network primitives the discovery stage
// orchestrates: local-subnet auto-detection, the bounded ICMP sweep with its
// pro-bing -> system-ping fallback, and shape helpers for IP/MAC strings.
//
// The primitives are kept separate from the stage that sequences them so each
// gets a narrow table test with mocked OS calls. Every value read off the wire
// (a ping reply, a reply TTL) is treated as untrusted: a garbage or absent
// signal collapses to "not live" / zero, never a crash (V5/V7).
package netutil

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// overlayPrefixes are interface-name prefixes that denote virtual/overlay links
// (loopback, tunnels, VPNs, container bridges, veth pairs, point-to-point WAN).
// A local-LAN sweep must exclude them: their addresses are not a physical
// segment we want to probe.
var overlayPrefixes = []string{
	"lo", "tun", "tap", "wg", "nebula", "tailscale", "docker", "br-", "veth",
	"virbr", "ppp", "sit", "ipip", "gre", "gretap", "ham", "utm",
}

// isOverlayName reports whether an interface name begins with a known
// overlay/virtual prefix (case-insensitive).
func isOverlayName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range overlayPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// ifaceView is the minimal shape of a network interface the LAN enumeration
// needs. Extracting it from net.Interface lets tests drive the enumeration with
// fixtures instead of the host's real interfaces.
type ifaceView struct {
	name  string
	flags net.Flags
	addrs []*net.IPNet
}

// LocalLANNetworks enumerates the real LAN networks attached to this host for
// use as the default sweep scope when no explicit --cidr is given. It excludes
// loopback, down, point-to-point and overlay/virtual interfaces, and
// link-local/loopback addresses, returning the IPv4 network/prefix (e.g.
// "192.168.1.0/24") of each remaining address. On enumeration failure or an
// empty result it returns a best-effort single-/24 fallback.
func LocalLANNetworks() []string {
	real, err := net.Interfaces()
	if err != nil {
		return fallbackNetworks()
	}
	views := make([]ifaceView, 0, len(real))
	for _, ifc := range real {
		addrs, _ := ifc.Addrs()
		nets := make([]*net.IPNet, 0, len(addrs))
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				nets = append(nets, ipnet)
			}
		}
		views = append(views, ifaceView{name: ifc.Name, flags: ifc.Flags, addrs: nets})
	}
	out := localLANNetworksFrom(views)
	if len(out) == 0 {
		return fallbackNetworks()
	}
	return out
}

// localLANNetworksFrom is the pure core of LocalLANNetworks over an injectable
// interface list, so the exclusion rules can be tested deterministically.
func localLANNetworksFrom(views []ifaceView) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range views {
		if v.flags&net.FlagLoopback != 0 || v.flags&net.FlagUp == 0 {
			continue
		}
		if v.flags&net.FlagPointToPoint != 0 {
			continue
		}
		if isOverlayName(v.name) {
			continue
		}
		for _, ipnet := range v.addrs {
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // IPv4-only sweep (FUT-02 defers IPv6 discovery)
			}
			if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			network := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}
			s := network.String()
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// fallbackNetworks returns a best-effort single /24 around the host's primary
// outbound IPv4 address, discovered via a route lookup that sends no packets. It
// returns an empty slice when no primary address can be determined — an empty
// scope yields zero live hosts but still a complete, valid payload (ENG-06).
func fallbackNetworks() []string {
	// Dialing a UDP socket to a documentation-range address performs the local
	// route+bind without transmitting anything, revealing the primary source IP.
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1 (RFC 5737), no traffic
	if err != nil {
		return []string{}
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return []string{}
	}
	ip4 := ua.IP.To4()
	if ip4 == nil {
		return []string{}
	}
	network := &net.IPNet{IP: ip4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}
	return []string{network.String()}
}

// looksLikeMAC reports whether s has the shape of a colon-separated 48-bit MAC.
// Used to filter kernel ARP-cache rows (shape validation before trust, V5).
func looksLikeMAC(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

// parsePrefixOrAddr parses a scope token as an IPv4 CIDR prefix, or as a bare
// IPv4 address treated as a /32. Non-IPv4 and malformed tokens return ok=false.
func parsePrefixOrAddr(token string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(token); err == nil {
		if !p.Addr().Is4() {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(token); err == nil && a.Is4() {
		return netip.PrefixFrom(a, 32), true
	}
	return netip.Prefix{}, false
}
