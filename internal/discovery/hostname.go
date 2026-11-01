// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"sort"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/netutil"
	"github.com/59k-ai/cysec-scanner/internal/oui"
)

// Hostname resolvers, exposed as injectable seams so the enrichment can be proven
// deterministically without real DNS/mDNS/NetBIOS traffic.
var (
	resolveRDNS    = netutil.ReverseDNS
	resolveMDNS    = netutil.ResolveMDNS
	resolveNetBIOS = netutil.NetBIOSNodeStatus
)

// Per-resolver timeouts. Each is short and per-host so one silent host never
// stalls the run; resolution is best-effort and any miss returns "".
const (
	rdnsTimeout    = 500 * time.Millisecond
	mdnsTimeout    = 500 * time.Millisecond
	netbiosTimeout = 500 * time.Millisecond
)

// enrichHostnames resolves a hostname for each collected host and records which
// resolvers answered. For every host it queries all three resolvers (honoring
// ctx), sets the asset hostname from the first non-empty result in the
// rDNS -> mDNS -> NetBIOS precedence order, and sets a per-resolver hit flag for
// EACH resolver that returned a name — independent of precedence. A host where
// nothing answered keeps an empty hostname and all three flags false, leaving the
// payload strict-valid.
//
// NetBIOS also answers with a unit ID, used as the host's MAC (and vendor) only
// when the ARP cache gave none; see the comment at the assignment below.
//
// The hit flags are internal bookkeeping on the keyed host record (no new payload
// field): they are the producer the classification enrichment consumes to emit
// the mdns/netbios presence evidence, so a host that answered mDNS but lost the
// name to rDNS still carries its mdns flag.
func enrichHostnames(ctx context.Context, entries map[string]hostEntry) {
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// The unit-ID MAC fallback is L2 evidence, so it applies on local segments
	// only. With the ARP cache hidden, L2 enrichment never marked routed hosts.
	local := localNetworks()

	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		e := entries[id]

		rdns := resolveRDNS(ctx, e.ip, rdnsTimeout)
		mdns := resolveMDNS(ctx, e.ip, mdnsTimeout)
		nbstat := resolveNetBIOS(ctx, e.ip, netbiosTimeout)
		netbios := nbstat.Name

		e.rdnsHit = rdns != ""
		e.mdnsHit = mdns != ""
		e.netbiosHit = netbios != ""

		switch {
		case rdns != "":
			e.hostname = rdns
		case mdns != "":
			e.hostname = mdns
		case netbios != "":
			e.hostname = netbios
		}

		// The node-status unit ID is a fallback MAC source for a host the ARP
		// cache did not cover (macOS 27 hides the cache without administrator
		// rights). An ARP MAC always wins, so output is unchanged wherever ARP
		// answered. A routed or off-segment host keeps a null MAC (DISC-03). The
		// value is self-reported, so the external id is not re-keyed to it and
		// classification evidence records its source.
		if e.mac == nil && !e.routed && nbstat.MAC != "" && ipInAnyCIDR(e.ip, local) {
			m := nbstat.MAC
			e.mac = &m
			e.macVendor = oui.LookupVendor(m)
			e.macFromNetBIOS = true
		}

		entries[id] = e
	}
}
