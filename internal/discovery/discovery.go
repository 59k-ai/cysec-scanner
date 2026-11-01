// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package discovery is the pipeline's discovery stage (DISC-01): it resolves the
// scan scope (explicit CIDRs or the auto-detected local subnet), ICMP-sweeps it
// for live hosts, and turns each live host into a v5 payload.AssetItem written
// into the shared accumulator.
//
// This phase builds the base IP-keyed asset only. Later enrichment plans harvest
// MAC/vendor and resolve hostnames, and may re-key the asset's external_id from
// ip:<ip> to a stabler identity — so hosts are collected into an internal set
// first (recording each reply TTL for a later OS-fingerprint hint) and finalized
// into assets at the END of the run, not streamed mid-sweep.
package discovery

import (
	"context"
	"sort"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/netutil"
	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
)

// Injectable seams the discovery stage drives the host world through, overridable
// in tests so the end-to-end path can be proven without real packets, OS reads or
// a live network. sweepHosts enumerates live hosts; arpTable reads the kernel ARP
// cache; localNetworks reports this host's local segments (used both as the
// default sweep scope and to decide whether an L2-silent host is routed);
// localInterfaceMACs maps this host's own IPv4 addresses to their interface MAC.
//
// sweepHosts keeps the plain Sweep signature so existing overrides stay valid.
// Its default routes through netutil.SweepObserved with the per-run observer
// carried on ctx (see withSweepObserver), so live progress needs no new seam
// shape. sweepPing is the liveness seam handed to the sweep (nil = the
// capability-selected default pinger).
var (
	sweepHosts    = observedSweep
	sweepPing     netutil.PingFunc
	arpTable      = netutil.ARPTable
	localNetworks = netutil.LocalLANNetworks

	localInterfaceMACs = netutil.LocalInterfaceMACs
)

// sweepObserverKey carries a run's netutil.SweepObserver on the context into the
// default sweepHosts seam. It is package-private: nothing outside discovery
// reads or sets it.
type sweepObserverKey struct{}

// withSweepObserver returns ctx carrying obs for the default sweep seam.
func withSweepObserver(ctx context.Context, obs netutil.SweepObserver) context.Context {
	return context.WithValue(ctx, sweepObserverKey{}, obs)
}

// observedSweep is the default sweepHosts: netutil.SweepObserved with whatever
// observer the run put on ctx (none = plain Sweep behaviour).
func observedSweep(ctx context.Context, cidrs []string, caps capabilities.Capabilities, ping netutil.PingFunc) []netutil.SweepResult {
	obs, _ := ctx.Value(sweepObserverKey{}).(netutil.SweepObserver)
	return netutil.SweepObserved(ctx, cidrs, caps, ping, obs)
}

// hostEntry is one live host collected during a run, before it is finalized into
// an asset. ttl is the best-effort reply TTL kept for a later OS-fingerprint
// hint (attacker-spoofable, low confidence). mac/macVendor are the post-sweep
// Layer-2 enrichment (nil = not observed); routed marks a confirmed off-segment
// host carrying the DISC-03 "not on local segment" state.
//
// hostname is the resolved (sanitized) name set on the asset; it is "" when no
// resolver answered. rdnsHit/mdnsHit/netbiosHit record WHICH resolvers actually
// answered — independent of which name won precedence — as internal bookkeeping
// (no new payload field). They are the producer the classification enrichment
// reads to emit the mdns/netbios presence evidence; it does not re-probe.
type hostEntry struct {
	ip         string
	ttl        int
	mac        *string
	macVendor  *string
	routed     bool
	hostname   string
	rdnsHit    bool
	mdnsHit    bool
	netbiosHit bool
	// macFromNetBIOS marks a MAC taken from the NetBIOS node-status unit ID
	// (self-reported by the host) rather than the ARP cache.
	macFromNetBIOS bool
	// macFromLocalInterface marks a MAC taken from this machine's own interface,
	// because its own IP is never in its own neighbour cache.
	macFromLocalInterface bool
}

// Run resolves the scope, sweeps it, and writes one base AssetItem per live host
// into the accumulator. It returns nil on an empty or fully-degraded sweep: zero
// live hosts still yields a complete, strict-valid v5 payload (ENG-06).
func Run(ctx context.Context, st *scanstate.ScanState, caps capabilities.Capabilities, cidrs []string) error {
	scope := cidrs
	if len(scope) == 0 {
		scope = localNetworks()
	}

	// The sweep selects its live path from caps; a fully-degraded host (no
	// unprivileged ICMP socket and no system ping) yields zero hosts, not an
	// error. The rest of Run tolerates an empty result and still produces a
	// complete, Normalize-able payload (ENG-06 graceful degradation).
	//
	// Live progress (D-01/D-02): every completed probe advances the discovery
	// stage counter, and each live reply surfaces immediately as a bare host row.
	// The enriched row follows from AddAsset below. Both are no-ops without an
	// observer, and neither touches the committed assets.
	obs := func(ip string, alive bool, done, total int) {
		st.ReportProgress("discovery", done, total)
		if alive {
			st.ReportHostSeen(ip)
		}
	}
	results := sweepHosts(withSweepObserver(ctx, obs), scope, caps, sweepPing)

	// Collect live hosts into an internal set keyed by external_id. ip:<ip> is
	// the only identity known from the sweep; L2 enrichment re-keys/harvests here
	// before anything is committed to the payload.
	entries := map[string]hostEntry{}
	for _, r := range results {
		id := externalID(r.IP)
		if _, ok := entries[id]; !ok {
			entries[id] = hostEntry{ip: r.IP, ttl: r.TTL}
		}
	}

	// Post-sweep Layer-2 enrichment (DISC-02/DISC-03): harvest ARP-only hosts,
	// assign MAC/vendor and stabilize identity (ip:<ip> -> mac:<mac>), and mark
	// confirmed routed hosts. Runs only when the ARP cache was readable — without
	// an L2 probe a routed host is indistinguishable from "not observed", so the
	// whole set stays fully null in that case.
	//
	// The resolved scan scope bounds the ARP harvest: the kernel ARP cache holds
	// neighbours from every interface (docker/VPN/other-segment/stale entries), so
	// an ARP-only host is only folded into the asset set when its IP is within
	// scope. localNetworks() stays the separate routed-vs-local yardstick for the
	// DISC-03 encoding of hosts that DID answer the sweep.
	if caps.ARPCache {
		enrichL2(entries, arpTable(), scope, localNetworks())
	}

	// Own-interface MAC: a result that is one of this machine's own IPs takes the
	// MAC of the interface carrying it. It runs whether or not the cache was
	// readable, since the interface list does not depend on it; before the
	// hostname pass, so the NetBIOS self-reported fallback (which only fills an
	// empty MAC) can never claim this host; and before AddAsset, so the live host
	// event and the final asset carry the same identity.
	enrichLocalMAC(entries, localInterfaceMACs())

	// Hostname enrichment (DISC-04): resolve a human-meaningful name per host via
	// rDNS, mDNS and NetBIOS. Runs AFTER L2 enrichment (so it keys off the stable
	// mac:<mac> identity where one was assigned) and BEFORE the final AddAsset.
	enrichHostnames(ctx, entries)

	// Finalize into assets at the end, in deterministic order. Classification
	// enrichment (DISC-05) runs LAST: it assembles each asset's
	// classification_evidence from the signals the L2 + hostname passes already
	// recorded (vendor, reply TTL, mDNS/NetBIOS hit flags), MERGING into the
	// same AssetItem.Classification so a routed host's l2_segment key survives.
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := entries[id]
		a := buildAsset(id, e)
		classifyAsset(&a, e)
		st.AddAsset(a)
	}
	return nil
}

// externalID is the per-asset identity. Only the IP is known this phase, so the
// id is ip:<ip>; later enrichment re-keys to a stabler mac:<mac> when available.
func externalID(ip string) string {
	return "ip:" + ip
}

// buildAsset maps one collected host onto a v5 AssetItem. Every required nested
// container is an empty literal (never nil) so the asset marshals strict-valid
// without relying solely on payload.Normalize(). Discovery never claims a host
// is managed or internet-facing — the cloud owns exposure truth.
//
// Layer-2 state (DISC-02/DISC-03): a local-segment host carries a real
// mac_address + mac_vendor; a confirmed routed host carries a null mac_address,
// the "not on local segment" sentinel in mac_vendor, and an l2_segment=routed
// classification evidence key; a host never L2-probed stays fully null (nil
// mac_address + nil mac_vendor + nil classification).
func buildAsset(id string, e hostEntry) payload.AssetItem {
	ip := e.ip
	a := payload.AssetItem{
		ExternalID:     id,
		Hostname:       e.hostname,
		FQDN:           e.hostname,
		IPAddress:      &ip,
		Managed:        false,
		InternetFacing: false,
		Services:       []payload.ServiceItem{},
		NetworkAliases: []payload.NetworkAliasItem{},
		MACAddress:     e.mac,
		MACVendor:      e.macVendor,
	}
	if e.routed {
		sentinel := macVendorNotOnLocalSegment
		a.MACAddress = nil
		a.MACVendor = &sentinel
		a.Classification = &payload.ClassificationEvidence{
			AssetType:     routedAssetType,
			Evidence:      map[string]string{evidenceKeyL2Segment: evidenceValueRouted},
			SecurityFlags: []string{},
		}
	}
	return a
}
