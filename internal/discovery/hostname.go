// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"sort"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/netutil"
)

// Hostname resolvers, exposed as injectable seams so the enrichment can be proven
// deterministically without real DNS/mDNS/NetBIOS traffic.
var (
	resolveRDNS    = netutil.ReverseDNS
	resolveMDNS    = netutil.ResolveMDNS
	resolveNetBIOS = netutil.NetBIOSName
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

	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		e := entries[id]

		rdns := resolveRDNS(ctx, e.ip, rdnsTimeout)
		mdns := resolveMDNS(ctx, e.ip, mdnsTimeout)
		netbios := resolveNetBIOS(ctx, e.ip, netbiosTimeout)

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

		entries[id] = e
	}
}
