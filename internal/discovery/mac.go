// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"net/netip"
	"sort"

	"github.com/59k-ai/cysec-scanner/internal/oui"
)

// DISC-03 Layer-2 segment wire encoding. These literals are the single source of
// truth for a host's L2 segment state and are consumed verbatim by the cloud
// ingest, so they are a near-one-way wire choice — confirmed before first ship.
//
// A confirmed routed host (answered ICMP, has no ARP entry, and lies outside
// every local segment) carries a null mac_address, macVendorNotOnLocalSegment as
// its mac_vendor, and evidence[evidenceKeyL2Segment] = evidenceValueRouted. This
// is deliberately distinct from "not observed" (null mac_address + null
// mac_vendor + no l2_segment evidence key), which is what a host that was never
// L2-probed carries.
const (
	// macVendorNotOnLocalSegment is the mac_vendor sentinel for a routed host.
	// It is intentionally NOT a MAC-format string: mac_address stays null for a
	// routed host, and this human-readable sentinel occupies mac_vendor so the
	// cloud has a parseable, never-blank signal.
	macVendorNotOnLocalSegment = "(not on local segment)"
	// evidenceKeyL2Segment is the classification-evidence key recording a host's
	// L2 segment relationship.
	evidenceKeyL2Segment = "l2_segment"
	// evidenceValueRouted is the evidenceKeyL2Segment value for a routed host.
	evidenceValueRouted = "routed"
	// routedAssetType labels a routed host's classification evidence. The full
	// deterministic asset-type rule engine lands in a later phase; discovery
	// never fabricates a specific type, so the carried evidence stays "unknown".
	routedAssetType = "unknown"
)

// enrichL2 adds Layer-2 identity to the collected host set using the post-sweep
// ARP cache. The caller invokes it only when the ARP cache was actually readable
// (the capability layer's ARPCache): a host that was never L2-probed must stay
// "not observed" (fully null), which is indistinguishable from a routed host
// unless an L2 probe is known to have been attempted.
//
// In order it (1) harvests hosts that answered ARP but stayed ICMP-silent into
// the set — but ONLY those within the resolved scan scope — (2) assigns
// mac_address/mac_vendor from the ARP entry and the embedded OUI registry,
// re-keying a host's external_id from ip:<ip> to mac:<mac> for a stable cross-run
// identity — guarding a MAC already claimed by another asset so a shared/proxy
// MAC never collapses two hosts into one — and (3) marks a confirmed routed host
// with the DISC-03 sentinel + evidence. The set is mutated in place BEFORE any
// asset is committed, so stabilization needs no accumulator re-key.
//
// scope is the resolved scan scope (explicit --cidr, else localNetworks); it
// bounds the harvest so a stale/other-interface ARP neighbour the operator never
// asked to scan does not become an asset. localCIDRs is the separate local-segment
// yardstick for the routed/not-observed decision in (3); a host that ANSWERED the
// sweep is in scope by construction, so the scope bound only ever drops ARP-only
// harvest candidates.
func enrichL2(entries map[string]hostEntry, arp map[string]string, scope, localCIDRs []string) {
	// (1) Harvest ARP-only hosts (answered ARP, ICMP-silent) that fall within the
	// resolved scan scope. The kernel ARP cache spans every interface, so an entry
	// outside scope (docker/VPN/other-segment/stale) must not become an asset — it
	// never answered the sweep and is not something the operator asked to scan. At
	// harvest time nothing is re-keyed yet, so every present host is still keyed
	// ip:<ip>.
	for ip := range arp {
		if !ipInAnyCIDR(ip, scope) {
			continue
		}
		id := externalID(ip)
		if _, ok := entries[id]; !ok {
			entries[id] = hostEntry{ip: ip}
		}
	}

	// (2)+(3) Deterministic order so the claimed-MAC guard is stable across runs.
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	claimed := map[string]bool{}
	for _, id := range ids {
		e, ok := entries[id]
		if !ok {
			continue // already re-keyed under a mac:<mac> id earlier this pass
		}
		mac, hasMAC := arp[e.ip]
		if hasMAC {
			m := mac
			e.mac = &m
			e.macVendor = oui.LookupVendor(mac)
			macID := "mac:" + mac
			if macID != id && !claimed[macID] {
				if _, exists := entries[macID]; !exists {
					delete(entries, id)
					entries[macID] = e
					claimed[macID] = true
					continue
				}
			}
			claimed[macID] = true
			entries[id] = e
			continue
		}
		// No ARP entry. A host outside every local segment that still answered
		// ICMP is confirmed routed (DISC-03). A host within a local segment but
		// absent from the cache stays "not observed" (fully null).
		if !ipInAnyCIDR(e.ip, localCIDRs) {
			e.routed = true
			entries[id] = e
		}
	}
}

// enrichLocalMAC fills the MAC of a host that is this machine itself. own maps
// this machine's IPv4 addresses to their interface MAC (netutil.LocalInterfaceMACs).
// A host never has its own address in its own neighbour cache, so without this
// the scanning machine is the one local host that always shows no MAC.
//
// A MAC another source already set is never overridden, and a routed host keeps
// the DISC-03 null MAC and sentinel. Unlike the NetBIOS unit ID, this MAC
// re-keys the external id to mac:<mac> exactly like the ARP path: the value
// comes from this machine's own OS interface table, not from what a remote host
// says about itself, so it is as authoritative as the cache. The same
// claimed-MAC guard applies, so a secondary address on one interface, or a MAC
// an ARP-sourced asset already holds, never collapses two assets. The GUI keys
// rows by IP, so the re-key never duplicates a row.
func enrichLocalMAC(entries map[string]hostEntry, own map[string]string) {
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		e, ok := entries[id]
		if !ok {
			continue // already re-keyed under a mac:<mac> id earlier this pass
		}
		if e.mac != nil || e.routed {
			continue
		}
		mac, isOwn := own[e.ip]
		if !isOwn {
			continue
		}
		m := mac
		e.mac = &m
		e.macVendor = oui.LookupVendor(mac)
		e.macFromLocalInterface = true
		macID := "mac:" + mac
		if macID != id {
			if _, exists := entries[macID]; !exists {
				delete(entries, id)
				entries[macID] = e
				continue
			}
		}
		entries[id] = e
	}
}

// ipInAnyCIDR reports whether ip falls within any of the given IPv4 CIDRs (a bare
// address is treated as itself). A malformed ip or CIDR is ignored, never a
// panic — the host simply fails the membership test.
func ipInAnyCIDR(ip string, cidrs []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			if p.Contains(addr) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(c); err == nil && a == addr {
			return true
		}
	}
	return false
}
