package netutil

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// PingFunc reports whether an IP is live, plus a best-effort reply TTL (0 when
// unknown/unavailable). It is the injectable seam the sweep probes each host
// through, so tests drive liveness deterministically without real packets.
type PingFunc func(ctx context.Context, ip string, timeout time.Duration) (live bool, ttl int)

// icmpProbe and systemProbe are the two layers of pingHost, kept as package
// seams so a test can prove the fallback path is taken. icmpProbe is the
// unprivileged pro-bing UDP-ICMP attempt; systemProbe shells the OS `ping`.
var (
	icmpProbe   = proBingProbe
	systemProbe = systemPing
)

// pingHost probes one host: it tries the unprivileged pro-bing UDP-ICMP path
// first, and on any failure or no-reply falls back to the system `ping` binary.
// The fallback is not optional on Linux — stock net.ipv4.ping_group_range
// usually refuses the UDP-ICMP socket, so without it a default sweep finds
// almost nothing.
func pingHost(ctx context.Context, ip string, timeout time.Duration) (bool, int) {
	if live, ttl := icmpProbe(ctx, ip, timeout); live {
		return true, ttl
	}
	return systemProbe(ctx, ip, timeout)
}

// proBingProbe runs a single unprivileged (UDP-ICMP) echo via pro-bing. A reply
// yields live=true and the reply TTL as a low-confidence OS hint; any error or
// a zero-reply run yields (false, 0) so pingHost moves to the fallback.
func proBingProbe(ctx context.Context, ip string, timeout time.Duration) (bool, int) {
	p, err := probing.NewPinger(ip)
	if err != nil {
		return false, 0
	}
	p.SetPrivileged(false) // UDP-ICMP, no CAP_NET_RAW
	p.Count = 1
	p.Timeout = timeout
	var ttl int
	p.OnRecv = func(pkt *probing.Packet) { ttl = pkt.TTL }
	if err := p.RunWithContext(ctx); err != nil {
		return false, 0
	}
	if p.Statistics().PacketsRecv > 0 {
		return true, ttl
	}
	return false, 0
}

// systemPing shells the OS `ping` binary for one echo. It works unprivileged on
// Linux where the stock binary carries file capabilities. The IP is one of our
// own CIDR-enumerated hosts, never attacker input, and is passed as a discrete
// argv element with no shell, so there is no command-injection surface.
func systemPing(ctx context.Context, ip string, timeout time.Duration) (bool, int) {
	var fam []string
	if strings.Contains(ip, ":") {
		fam = []string{"-6"}
	}
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	args := append(fam, "-c", "1", "-W", strconv.Itoa(secs), "-n", "-q", ip)
	out, _ := exec.CommandContext(ctx, "ping", args...).Output()
	s := string(out)
	if strings.Contains(s, "1 received") || strings.Contains(s, "1 packets received") {
		return true, parseReplyTTL(s)
	}
	return false, 0
}

// parseReplyTTL extracts a "ttl=NN" hint from ping output when present (best
// effort — the quiet summary usually omits it, yielding 0). The TTL is a
// low-confidence, attacker-spoofable hint only; a garbage value collapses to 0.
func parseReplyTTL(s string) int {
	low := strings.ToLower(s)
	i := strings.Index(low, "ttl=")
	if i < 0 {
		return 0
	}
	n := 0
	for _, c := range low[i+len("ttl="):] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
