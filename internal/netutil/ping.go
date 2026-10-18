package netutil

import (
	"context"
	"os"
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
	cmd := exec.CommandContext(ctx, "ping", args...)
	// Force a stable C locale so neither the liveness decision nor the TTL hint
	// depends on the host's LANG/LC_ALL. The DACH target market commonly runs a
	// German (de_DE.*) locale, where iputils localizes its stats line ("… 1
	// empfangen") — an English-substring match would then miss a live host on the
	// primary Linux liveness path. Liveness itself comes from the exit code below,
	// but the forced locale also keeps the TTL "ttl=" token stable.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	return pingResultLive(out, err)
}

// pingResultLive maps a completed `ping -c 1` run onto (live, ttlHint). Liveness
// is decided by the process EXIT STATUS, never the output text: `ping -c 1`
// exits 0 only when an echo reply arrived, so a nil error (exit 0) is live
// regardless of the stdout language — this removes the English-substring
// dependency entirely. A non-zero exit is the normal "no reply" case (surfaced
// as *exec.ExitError with code 1) and maps to not-live, not an error; any other
// failure (binary missing, context deadline) is likewise treated as not-live and
// never panics. The output string is consulted ONLY for the best-effort TTL hint.
func pingResultLive(out []byte, runErr error) (bool, int) {
	if runErr != nil {
		return false, 0
	}
	return true, parseReplyTTL(string(out))
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
	count := 0
	for _, c := range low[i+len("ttl="):] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		count++
		// A TTL is 0..255. Cap the digit run (never accumulate past 3 digits) so a
		// hostile/garbage reply cannot overflow int, and bail once we exceed the
		// IPv4 ceiling.
		if count >= 3 || n > 255 {
			break
		}
	}
	if n > 255 {
		return 0 // out of the valid 0..255 band → treat as garbage
	}
	return n
}
