// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"net"
	"strings"
)

// normalizeMAC validates s as a 48-bit MAC and returns it in canonical
// lower-case colon form. It rejects non-MAC strings, non-48-bit addresses, the
// all-zero address (an incomplete/unresolved cache entry), the macOS redaction
// placeholder 02:00:00:00:00:00 and any group address
// (I/G bit set: broadcast ff:ff:ff:ff:ff:ff, multicast 01:00:5e:...), so a caller
// can trust any returned value is a real unicast hardware address
// (shape-before-trust, V5). A readable macOS cache lists the subnet broadcast
// address, which lies inside the scan scope and would otherwise become an asset.
func normalizeMAC(s string) (string, bool) {
	hw, err := net.ParseMAC(padColonOctets(strings.TrimSpace(s)))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	if hw[0]&0x01 != 0 {
		return "", false // group (broadcast/multicast) address, never a device
	}
	mac := hw.String() // lower-case, colon-separated
	if mac == "00:00:00:00:00:00" || mac == macRedactedPlaceholder {
		return "", false
	}
	return mac, true
}

// macRedactedPlaceholder is what macOS 27 reports in place of a MAC it hides
// from the caller (IPv6 neighbours, the Mac's own interfaces). It is a privacy
// placeholder, never a device's address.
const macRedactedPlaceholder = "02:00:00:00:00:00"

// padColonOctets zero-pads one-digit groups of a six-group colon MAC. macOS/BSD
// arp prints octets unpadded ("74:24:9f:6:c8:ff"), which net.ParseMAC rejects.
// Anything that is not six colon groups of one or two characters is returned
// unchanged for net.ParseMAC to judge.
func padColonOctets(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return s
	}
	for i, p := range parts {
		switch len(p) {
		case 1:
			parts[i] = "0" + p
		case 2:
		default:
			return s
		}
	}
	return strings.Join(parts, ":")
}

// arpCommandArgs returns the arguments for the `arp` table dump on goos.
// macOS/BSD `arp -a` reverse-resolves every entry, which with a few hundred
// cached neighbours takes several seconds and overruns the read timeout; -n
// prints numeric addresses only. Windows arp has no lowercase -n (its -N takes an
// interface address) and does not resolve names, so it keeps plain -a.
func arpCommandArgs(goos string) []string {
	if goos == "windows" {
		return []string{"-a"}
	}
	return []string{"-an"}
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

// parseARPCommand parses the output of `arp -an` (BSD/macOS) or `arp -a`
// (Windows) into an {ip: mac} map. The format differs per platform — BSD/macOS
// print "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0" (octets unpadded), Windows prints
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
