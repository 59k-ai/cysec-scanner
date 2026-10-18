package netutil

import (
	"net"
	"strings"
)

// normalizeMAC validates s as a 48-bit MAC and returns it in canonical
// lower-case colon form. It rejects non-MAC strings, non-48-bit addresses and
// the all-zero address (an incomplete/unresolved cache entry), so a caller can
// trust any returned value is a real hardware address (shape-before-trust, V5).
func normalizeMAC(s string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	mac := hw.String() // lower-case, colon-separated
	if mac == "00:00:00:00:00:00" {
		return "", false
	}
	return mac, true
}

// parseProcNetARP parses the Linux /proc/net/arp table into an {ip: mac} map.
// The first line is the column header and is skipped; a row with fewer than four
// fields, a non-IP first column, an all-zero/unresolved hardware address, or a
// non-MAC-shaped address is dropped rather than trusted. The kernel cache is
// attacker-influenceable (a host controls the MAC it advertises), so every row
// is shape-validated and a malformed line is skipped, never a panic (T-3-04).
func parseProcNetARP(data string) map[string]string {
	out := map[string]string{}
	for i, line := range strings.Split(data, "\n") {
		if i == 0 {
			continue // column header
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		mac, ok := normalizeMAC(fields[3])
		if !ok {
			continue
		}
		out[ip] = mac
	}
	return out
}

// parseARPCommand parses the output of `arp -a` into an {ip: mac} map. The
// format differs per platform — BSD/macOS print
// "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0", Windows prints
// "192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic" — so each line is scanned for the
// first IP-shaped token and the first MAC-shaped token (net.ParseMAC accepts
// both colon and hyphen forms). A line lacking either is skipped; an incomplete
// entry (e.g. "(incomplete)") yields no MAC and is dropped.
func parseARPCommand(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		var ip, mac string
		for _, tok := range strings.Fields(line) {
			t := strings.Trim(tok, "()[]")
			if ip == "" && net.ParseIP(t) != nil {
				ip = t
				continue
			}
			if mac == "" {
				if m, ok := normalizeMAC(t); ok {
					mac = m
				}
			}
		}
		if ip != "" && mac != "" {
			res[ip] = mac
		}
	}
	return res
}
