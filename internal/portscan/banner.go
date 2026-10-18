// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"net"
	"strings"
	"time"
)

// Banner capture for the port stage (PORT-04, D-06/D-07). Every read here follows
// the project's never-raises bounded-socket discipline: a deadline on the read,
// a hard byte cap, and any error collapsed to an empty result — a dark, slow, or
// hostile endpoint yields nothing, never a hang or a panic. The target host is
// one of our own scope-enumerated addresses passed as a discrete argument (no
// shell, no injection surface), so the read is purely inbound evidence.

// maxBannerBytes caps a single plaintext banner read so a host that streams
// forever cannot exhaust the probe's memory or time budget.
const maxBannerBytes = 4096

// bannerResult is the evidence captured from an open port: the trimmed plaintext
// banner text and, later, the negotiated TLS version string (empty this phase —
// the TLS peek lands in a later plan).
type bannerResult struct {
	Text       string
	TLSVersion string
}

// grabBanner reads a bounded plaintext banner from an already-open connection.
// It sets a read deadline from the tier's banner budget, reads at most
// maxBannerBytes, and returns the trimmed text. Any read error (including a
// deadline on a connected-but-silent port) collapses to an empty result — it
// never raises and never blocks past the deadline.
func grabBanner(ctx context.Context, conn net.Conn, host string, port int, tier Tier) bannerResult {
	_ = ctx
	_ = host
	_ = port
	if tier.BannerTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(tier.BannerTimeout))
	}
	buf := make([]byte, maxBannerBytes)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return bannerResult{}
	}
	return bannerResult{Text: strings.TrimSpace(string(buf[:n]))}
}

// parseServiceIdentity extracts a structured product/service-version pair from a
// banner. It is a stub this phase (always nil,nil) — the light structured parse
// lands in a later plan and flows through the already-wired service-identity
// provenance labeling with no change to the orchestrator.
func parseServiceIdentity(port int, b bannerResult) (product, version *string) {
	_ = port
	_ = b
	return nil, nil
}

// bannerHints extracts a coarse product hint and an OS cue from a banner (e.g. an
// SSH comment string or an HTTP Server header). It is a stub this phase (always
// "",""); the extraction lands in a later plan. The aggregation that feeds the
// single per-asset product/OS hint already calls this per open port in ascending
// order, so the real hints flow through without re-touching the orchestrator.
func bannerHints(port int, b bannerResult) (productHint string, osCue string) {
	_ = port
	_ = b
	return "", ""
}
