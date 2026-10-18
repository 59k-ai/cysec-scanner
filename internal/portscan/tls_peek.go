// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// Minimal TLS evidence peek for the port stage (PORT-04, D-06). On a TLS port the
// grab does NOT read a plaintext banner; it drives a crypto/tls handshake over the
// SAME connection dialProbe already opened through the shared rate limiter — no
// second dial — and reads the negotiated version plus the leaf certificate common
// name as a banner-equivalent evidence string. Like the plaintext grab it is
// never-raises and bounded: any handshake error collapses to an empty result, and
// a handshake failure is NEVER mistaken for a closed port.

// tlsProbePorts are the TLS ports grabBanner hands to the handshake peek instead
// of the plaintext read path. Kept minimal (HTTPS + the common alt-HTTPS) — the
// peek is a cert-CN/version read, not a TLS fingerprint.
var tlsProbePorts = map[int]bool{
	443: true, 8443: true,
}

// defaultTLSHandshakeTimeout bounds the handshake when a tier declares no banner
// budget, so a stalled or hostile endpoint can never block the peek indefinitely.
const defaultTLSHandshakeTimeout = 2 * time.Second

// tlsPeek wraps an already-connected net.Conn (opened by dialProbe through the
// shared limiter — it opens NO new socket) in a TLS client and reads the
// negotiated version + leaf-cert common name as evidence.
//
// InsecureSkipVerify is deliberate: this is an evidence read of what is often
// self-signed internal gear (printers, NAS, management planes), not an
// authentication of the peer. We therefore never validate the certificate chain,
// and a chain/verify failure is NOT treated as a closed port — only an actual
// handshake error yields empty evidence. The handshake is bounded by both a conn
// deadline and a context timeout so a hostile endpoint that stalls the handshake
// cannot hang the probe or stall the rate limiter.
func tlsPeek(ctx context.Context, conn net.Conn, host string, tier Tier) bannerResult {
	timeout := tier.BannerTimeout
	if timeout <= 0 {
		timeout = defaultTLSHandshakeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// #nosec G402 -- InsecureSkipVerify is an intentional evidence read, not auth;
	// see the function doc. We read CN/version, we do not trust the peer.
	client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec
	if err := client.HandshakeContext(hctx); err != nil {
		return bannerResult{}
	}

	state := client.ConnectionState()
	ver := tls.VersionName(state.Version)
	cn := ""
	if len(state.PeerCertificates) > 0 {
		cn = sanitizeField(state.PeerCertificates[0].Subject.CommonName)
	}
	return bannerResult{Text: strings.TrimSpace(ver + " CN=" + cn), TLSVersion: ver}
}

// sanitizeField strips every control byte (including tab/CR/LF) from an untrusted
// single-line value such as a certificate common name, so a hostile cert cannot
// inject newlines or terminal escapes into the evidence string.
func sanitizeField(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return strings.TrimSpace(string(out))
}
