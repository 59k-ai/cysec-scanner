// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"context"
	"io"
	"net"
	"regexp"
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

// Banner parse regexes, compiled once. sshBannerRe captures the software token of
// an SSH-2.0 identification string; serverHeaderRe captures an HTTP Server header
// value in multiline mode (so a full response block is scanned line by line).
var (
	sshBannerRe    = regexp.MustCompile(`^SSH-2\.0-(\S+?)(?:\s|$)`)
	serverHeaderRe = regexp.MustCompile(`(?im)^Server:\s*(.+)$`)
)

// parseServiceIdentity light-parses an obvious product and service version out of
// a banner into the v5 product/service_version fields (D-07). It dispatches on the
// banner CONTENT, not the port, so it works regardless of which port the evidence
// came from: an SSH-2.0 identification string splits into software + version
// (e.g. "OpenSSH" / "9.6"), and an HTTP Server header becomes the product. It
// returns (nil, nil) whenever nothing parses — it never fabricates a value.
//
// Every value returned here is deliberately RAW: this function asserts no
// confidence, writes no provenance, and sets no authoritative OS field. The
// orchestrator (04-01) already labels each returned value low-confidence and
// source-tagged on the classification evidence map (D-08), so Phase 5 can override
// a light-parse value with a higher-fidelity match.
func parseServiceIdentity(port int, b bannerResult) (product, version *string) {
	_ = port
	text := b.Text
	if text == "" {
		return nil, nil
	}
	if m := sshBannerRe.FindStringSubmatch(text); m != nil {
		software, ver := splitSoftwareVersion(m[1])
		if software == "" {
			return nil, nil
		}
		if ver != "" {
			return strPtr(software), strPtr(ver)
		}
		return strPtr(software), nil
	}
	if m := serverHeaderRe.FindStringSubmatch(text); m != nil {
		if prod := strings.TrimSpace(m[1]); prod != "" {
			return strPtr(prod), nil
		}
	}
	return nil, nil
}

// bannerHints extracts a coarse product hint and an OS cue from a banner for the
// classifier (D-10). An SSH identification string implies a unix-like host
// ("linux" cue); an HTTP response is matched against a small substring map for a
// device product hint (router/openwrt/camera/nas/media/echo/printer) and an
// IIS/Microsoft Server header gives a "windows" cue. Both are empty when nothing
// matches. Like parseServiceIdentity these are low-confidence cues only — the
// provenance/precedence is owned upstream; this returns raw hint strings.
func bannerHints(port int, b bannerResult) (productHint string, osCue string) {
	_ = port
	text := b.Text
	if text == "" {
		return "", ""
	}
	if strings.HasPrefix(text, "SSH-2.0-") {
		// An SSH daemon (OpenSSH and friends) implies a unix-like operating system.
		return "", "linux"
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "routeros"):
		productHint = "router"
	case strings.Contains(lower, "openwrt") || strings.Contains(lower, "lede"):
		productHint = "openwrt"
	case strings.Contains(lower, "dvr"):
		productHint = "camera"
	case strings.Contains(lower, "synology") || strings.Contains(lower, "diskstation"):
		productHint = "nas"
	case strings.Contains(lower, "homerun") || strings.Contains(lower, "hdhr"):
		productHint = "media"
	case strings.Contains(lower, "echo") || strings.Contains(lower, "alexa") || strings.Contains(lower, "a113"):
		productHint = "echo"
	case strings.Contains(lower, "deskjet") || strings.Contains(lower, "laserjet") || strings.Contains(lower, "hp-chai"):
		productHint = "printer"
	}
	if strings.Contains(lower, "iis") || strings.Contains(lower, "microsoft") {
		osCue = "windows"
	}
	return productHint, osCue
}

// splitSoftwareVersion splits an SSH software token into software and version on
// the LAST underscore-or-dash (e.g. "OpenSSH_9.6" -> "OpenSSH","9.6"), mirroring
// the reference's last-separator rule. A token with no interior separator returns
// the whole token as software and an empty version.
func splitSoftwareVersion(s string) (software, version string) {
	idx := strings.LastIndexAny(s, "_-")
	if idx <= 0 || idx == len(s)-1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// strPtr returns a pointer to s — the v5 optional fields are *string so an
// absent value marshals to JSON null.
func strPtr(s string) *string { return &s }
