package netutil

// resolve.go holds reverse-DNS hostname resolution plus the shared hostname
// sanitizer. Every name returned here crosses a trust boundary (a PTR record is
// influenceable by whoever controls the reverse zone), so it is length-capped and
// stripped of control characters before it can reach an asset or a log line
// (V5/V7 — no log/display injection).

import (
	"context"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// maxHostnameLen caps a resolved hostname. A DNS name is at most 253 characters;
// anything longer is truncated rather than trusted as-is.
const maxHostnameLen = 253

// lookupAddr is the injectable reverse-DNS seam (the stdlib resolver by default)
// so tests drive resolution deterministically without real network lookups.
var lookupAddr = net.DefaultResolver.LookupAddr

// ReverseDNS returns the first PTR name for a resolvable IP, sanitized, and ""
// for an unresolvable IP or on timeout. The lookup runs under the smaller of the
// caller's context deadline and the given per-lookup timeout, so one slow host
// never stalls the sweep.
func ReverseDNS(ctx context.Context, ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	names, err := lookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return sanitizeHostname(names[0])
}

// sanitizeHostname makes an untrusted hostname safe to carry on an asset: it
// trims surrounding whitespace and the trailing root dot, strips control
// characters (bytes below 0x20 and DEL), and caps the length without splitting a
// multi-byte rune. An all-control-character name collapses to "".
func sanitizeHostname(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue // strip control characters
		}
		if b.Len()+utf8.RuneLen(r) > maxHostnameLen {
			break // length cap, rune-aware
		}
		b.WriteRune(r)
	}
	return b.String()
}
