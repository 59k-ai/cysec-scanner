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

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/netutil"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// Injectable seams the discovery stage drives the host world through, overridable
// in tests so the end-to-end path can be proven without real packets, OS reads or
// a live network. sweepHosts enumerates live hosts; arpTable reads the kernel ARP
// cache; localNetworks reports this host's local segments (used both as the
// default sweep scope and to decide whether an L2-silent host is routed).
var (
	sweepHosts    = netutil.Sweep
	arpTable      = netutil.ARPTable
	localNetworks = netutil.LocalLANNetworks
)

// hostEntry is one live host collected during a run, before it is finalized into
// an asset. ttl is the best-effort reply TTL kept for a later OS-fingerprint
// hint (attacker-spoofable, low confidence). mac/macVendor are the post-sweep
// Layer-2 enrichment (nil = not observed); routed marks a confirmed off-segment
// host carrying the DISC-03 "not on local segment" state.
type hostEntry struct {
	ip        string
	ttl       int
	mac       *string
	macVendor *string
	routed    bool
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
	results := sweepHosts(ctx, scope, caps, nil)

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
	if caps.ARPCache {
		enrichL2(entries, arpTable(), localNetworks())
	}

	// Finalize into assets at the end, in deterministic order.
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		st.AddAsset(buildAsset(id, entries[id]))
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
