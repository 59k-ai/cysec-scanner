package netutil

// mdns.go hand-rolls a one-packet multicast-DNS resolver (no external
// dependency). It sends a reverse-address PTR question to the mDNS group over an
// unprivileged UDP client socket and parses the reply with a strictly bounded DNS
// message parser: every label and length read is checked against the buffer, a
// compression pointer may never revisit an offset (loop guard), and the record
// count is capped — so a hostile responder can never make the parser hang,
// over-read, or panic (T-3-07). On any miss it returns "".

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	// mdnsMulticastAddr is the IPv4 multicast-DNS group/port (RFC 6762).
	mdnsMulticastAddr = "224.0.0.251:5353"
	// dnsClassINUnicast is class IN (0x0001) with the mDNS unicast-response (QU)
	// bit set, asking responders to answer our ephemeral source port directly.
	dnsClassINUnicast = 0x8001

	dnsTypeA   = 1
	dnsTypePTR = 12
	dnsTypeSRV = 33

	// Parser bounds. A DNS name is at most 255 bytes; label/record counts are
	// capped so a crafted reply cannot drive unbounded work.
	maxDNSNameBytes = 255
	maxDNSLabels    = 128
	maxDNSRecords   = 64
	// maxMDNSReply bounds a single read; mDNS replies fit comfortably below this.
	maxMDNSReply = 9000
)

// ResolveMDNS resolves a hostname for ip via a reverse-address (in-addr.arpa) PTR
// query to the mDNS group, returning the sanitized name on a hit and "" on a
// miss, timeout, or any malformed reply. It is best-effort: no responder on the
// segment simply yields "".
func ResolveMDNS(ctx context.Context, ip string, timeout time.Duration) string {
	rev, ok := reverseInAddrName(ip)
	if !ok {
		return ""
	}
	dst, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return ""
	}
	// An unbound ephemeral UDP socket (not a server): we send a unicast-requested
	// multicast query and receive the unicast reply. This is a client receive
	// socket, not an inbound listener (ENG-04).
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return ""
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.WriteToUDP(buildDNSQuery(rev, dnsTypePTR), dst); err != nil {
		return ""
	}
	buf := make([]byte, maxMDNSReply)
	for {
		if ctx.Err() != nil {
			return ""
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "" // deadline reached or read error — treat as a miss
		}
		if name := parseDNSHostname(buf[:n]); name != "" {
			return sanitizeHostname(name)
		}
	}
}

// reverseInAddrName builds the in-addr.arpa reverse name for an IPv4 address
// (10.0.0.1 -> "1.0.0.10.in-addr.arpa"). IPv6 and malformed inputs return false.
func reverseInAddrName(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return "", false
	}
	b := a.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), true
}

// buildDNSQuery encodes a single-question DNS query packet for name/qtype with
// the mDNS unicast-response class. Labels longer than 63 bytes are clamped.
func buildDNSQuery(name string, qtype uint16) []byte {
	out := []byte{
		0x00, 0x00, // transaction id
		0x00, 0x00, // flags: standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0x00) // root label
	out = append(out, byte(qtype>>8), byte(qtype))
	out = append(out, byte(dnsClassINUnicast>>8), byte(dnsClassINUnicast&0xFF))
	return out
}

// parseDNSHostname extracts the best host name from a DNS/mDNS reply, preferring
// a PTR target, then an SRV target, then an A-record owner name. It is fully
// bounded: it never reads past the buffer, never follows a looping compression
// pointer, and caps the number of records parsed. Any malformed structure
// collapses the whole parse to "".
func parseDNSHostname(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	ns := int(msg[8])<<8 | int(msg[9])
	ar := int(msg[10])<<8 | int(msg[11])

	off := 12
	// Skip the question section: a name followed by QTYPE + QCLASS.
	for i := 0; i < qd; i++ {
		_, next, ok := parseDNSName(msg, off)
		if !ok {
			return ""
		}
		off = next + 4
		if off > len(msg) {
			return ""
		}
	}

	total := an + ns + ar
	if total > maxDNSRecords {
		total = maxDNSRecords
	}

	var bestPTR, bestSRV, bestOwner string
	for i := 0; i < total; i++ {
		owner, next, ok := parseDNSName(msg, off)
		if !ok {
			return ""
		}
		off = next
		if off+10 > len(msg) {
			return ""
		}
		rtype := int(msg[off])<<8 | int(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		rdataStart := off + 10
		if rdataStart+rdlen > len(msg) {
			return ""
		}
		switch rtype {
		case dnsTypePTR:
			if name, _, ok := parseDNSName(msg, rdataStart); ok && bestPTR == "" {
				bestPTR = name
			}
		case dnsTypeSRV:
			if rdlen >= 7 {
				if name, _, ok := parseDNSName(msg, rdataStart+6); ok && bestSRV == "" {
					bestSRV = name
				}
			}
		case dnsTypeA:
			if bestOwner == "" && owner != "" {
				bestOwner = owner
			}
		}
		off = rdataStart + rdlen
	}
	for _, cand := range []string{bestPTR, bestSRV, bestOwner} {
		if cand != "" {
			return cand
		}
	}
	return ""
}

// parseDNSName decodes a DNS name starting at off. It returns the dotted name,
// the offset just past the name in the sequential stream (for the next field),
// and ok. Bounds: every byte is checked against the buffer; a compression
// pointer must point within the message and may never revisit an already-seen
// target (the seen set guarantees termination); the accumulated name length and
// label count are capped. Any violation returns ok=false.
func parseDNSName(msg []byte, off int) (string, int, bool) {
	var labels []string
	seen := map[int]bool{}
	jumped := false
	nextOff := off
	nameLen := 0

	for {
		if off < 0 || off >= len(msg) {
			return "", 0, false
		}
		b := int(msg[off])
		switch {
		case b == 0x00: // end of name
			off++
			if !jumped {
				nextOff = off
			}
			return strings.Join(labels, "."), nextOff, true
		case b&0xC0 == 0x00: // literal label
			start := off + 1
			end := start + b
			if end > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[start:end]))
			nameLen += b + 1
			if nameLen > maxDNSNameBytes || len(labels) > maxDNSLabels {
				return "", 0, false
			}
			off = end
			if !jumped {
				nextOff = off
			}
		case b&0xC0 == 0xC0: // compression pointer
			if off+1 >= len(msg) {
				return "", 0, false
			}
			ptr := (b&0x3F)<<8 | int(msg[off+1])
			if !jumped {
				nextOff = off + 2
				jumped = true
			}
			if ptr >= len(msg) || seen[ptr] {
				return "", 0, false // out of range or a loop
			}
			seen[ptr] = true
			off = ptr
		default: // 0x40 / 0x80 are reserved
			return "", 0, false
		}
	}
}
