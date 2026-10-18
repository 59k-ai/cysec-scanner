// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"io"
	"net"
	"strings"
	"time"
)

// Banner capture for the port stage (PORT-04, D-06/D-07). Every read here follows
// the project's never-raises bounded-socket discipline: a deadline on the read,
// a hard byte cap, and any error collapsed to an empty result — a dark, slow, or
// hostile endpoint yields nothing, never a hang or a panic. The target host is
// one of our own scope-enumerated addresses passed as a discrete argument (no
// shell, no injection surface), so the read is purely inbound evidence. Every
// captured byte is untrusted, so the text is control-char-sanitized before it
// leaves this layer.

// bannerResult is the evidence captured from an open port: the trimmed plaintext
// banner text and, on a TLS port, the negotiated TLS version string.
type bannerResult struct {
	Text       string
	TLSVersion string
}

// grabBanner captures bounded evidence from an already-open connection that
// dialProbe opened through the shared rate limiter. For a plaintext banner port
// it sets a read deadline from the tier's banner budget and reads at most
// maxBannerBytes: an HTTP port is sent a minimal HEAD probe first, every other
// banner port is read directly as a server-speaks-first greeting. A port that is
// not a banner port yields an empty result with no bytes sent or read. Any error
// (including a deadline on a connected-but-silent port) collapses to an empty
// result — it never raises and never blocks past the deadline.
func grabBanner(ctx context.Context, conn net.Conn, host string, port int, tier Tier) bannerResult {
	// A TLS port gets a handshake peek over this same limited connection instead
	// of a plaintext read — no second dial, so the connect stays under the limiter.
	if tlsProbePorts[port] {
		return tlsPeek(ctx, conn, host, tier)
	}
	if !bannerPorts[port] {
		return bannerResult{}
	}
	if tier.BannerTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(tier.BannerTimeout))
	}

	switch {
	case httpProbePorts[port]:
		// An HTTP server stays silent until it sees a request, so send a minimal
		// HEAD line (no body expected back) and then read the status + headers.
		req := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return bannerResult{}
		}
	case serverSpeaksFirst[port]:
		// The greeting is already in flight — read it directly, send nothing.
	default:
		// Other banner ports (RTSP, VNC, JetDirect) also greet or tolerate a bare
		// read; treat them like a server-speaks-first port.
	}

	// io.LimitReader enforces the byte cap exactly at the read boundary, so an
	// unbounded stream is truncated to the first maxBannerBytes deterministically
	// and can never over-read. io.ReadAll surfaces no error path — a deadline or a
	// reset simply ends the read with whatever bytes arrived.
	raw, _ := io.ReadAll(io.LimitReader(conn, maxBannerBytes))
	return bannerResult{Text: sanitizeBanner(raw)}
}

// sanitizeBanner strips non-printable control bytes from an untrusted banner,
// keeping tab/CR/LF so a multi-line HTTP header block survives for the later
// product parse, and trims surrounding whitespace. Dropping the other control
// characters keeps a hostile endpoint from smuggling terminal escapes into the
// evidence that reaches the payload.
func sanitizeBanner(raw []byte) string {
	out := make([]byte, 0, len(raw))
	for _, c := range raw {
		switch {
		case c == '\t' || c == '\n' || c == '\r':
			out = append(out, c)
		case c < 0x20 || c == 0x7f:
			// drop other control characters
		default:
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
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
