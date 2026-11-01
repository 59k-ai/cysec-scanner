// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

// netbios.go hand-rolls a NetBIOS NBSTAT node-status resolver (no external
// dependency). It sends a unicast node-status query (type 0x0021) to UDP/137 from
// an ephemeral source port over a connected UDP client socket and parses the
// returned names table, returning the <00> unique workstation name and the unit
// ID that follows the table (a Windows host reports its adapter MAC there). The parser is
// strictly bounded: the declared name count and each fixed-width entry are checked
// against the buffer, so a malformed or truncated reply collapses to "" without
// over-reading or panicking (T-3-08). On any miss it returns "".

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// nbstatType is the NBSTAT node-status query/record type.
	nbstatType = 0x0021
	// nbNameEntryLen is one names-table entry: a 15-byte name, a 1-byte suffix,
	// and 2 bytes of name flags.
	nbNameEntryLen = 18
	// nbSuffixWorkstation is the NetBIOS suffix for the workstation service.
	nbSuffixWorkstation = 0x00
	// nbFlagGroup is the group-name bit in a name-table entry's flags; a unique
	// name has it clear.
	nbFlagGroup = 0x8000
	// maxNBStatReply bounds a single reply read.
	maxNBStatReply = 1024
)

// NetBIOSStatus is the useful part of one NBSTAT node-status reply: the <00>
// unique workstation name and the unit ID as a validated unicast MAC. Either may
// be empty. The MAC is self-reported by the host (Samba usually sends zeros,
// which are rejected), so callers use it only when the ARP cache has nothing.
type NetBIOSStatus struct {
	Name string
	MAC  string
}

// NetBIOSName resolves a NetBIOS workstation name for ip via a unicast NBSTAT
// node-status query to UDP/137, returning the sanitized <00> unique name on a hit
// and "" on a miss, timeout, or malformed reply.
func NetBIOSName(ctx context.Context, ip string, timeout time.Duration) string {
	return NetBIOSNodeStatus(ctx, ip, timeout).Name
}

// NetBIOSNodeStatus sends one unicast NBSTAT node-status query to UDP/137 and
// returns the workstation name and unit-ID MAC from the reply; a miss, timeout
// or malformed reply yields the zero value. The connected UDP socket is an
// outbound client (net.Dial), never an inbound listener (ENG-04).
func NetBIOSNodeStatus(ctx context.Context, ip string, timeout time.Duration) NetBIOSStatus {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "137"))
	if err != nil {
		return NetBIOSStatus{}
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(buildNBStatQuery()); err != nil {
		return NetBIOSStatus{}
	}
	buf := make([]byte, maxNBStatReply)
	n, err := conn.Read(buf)
	if err != nil {
		return NetBIOSStatus{}
	}
	return parseNBStatStatus(buf[:n])
}

// buildNBStatQuery builds a NBSTAT node-status query for the "*" wildcard name.
func buildNBStatQuery() []byte {
	out := []byte{
		0x00, 0x00, // transaction id
		0x00, 0x00, // flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	out = append(out, 0x20) // encoded-name length (32)
	out = append(out, encodeNetBIOSWildcard()...)
	out = append(out, 0x00) // scope: root
	out = append(out, byte(nbstatType>>8), byte(nbstatType&0xFF))
	out = append(out, 0x00, 0x01) // class IN
	return out
}

// encodeNetBIOSWildcard first-level-encodes the 16-byte "*" NetBIOS name
// ('*' followed by 15 nulls) into its 32-byte half-ASCII form ("CKAAAA...AA").
func encodeNetBIOSWildcard() []byte {
	name := make([]byte, 16)
	name[0] = '*' // remaining 15 bytes stay null
	out := make([]byte, 32)
	for i, c := range name {
		out[i*2] = 'A' + (c >> 4)
		out[i*2+1] = 'A' + (c & 0x0F)
	}
	return out
}

// parseNBStatReply extracts the <00> unique workstation name from a NBSTAT
// node-status reply, or "" if the reply is empty, malformed, or truncated.
func parseNBStatReply(buf []byte) string {
	return parseNBStatStatus(buf).Name
}

// parseNBStatStatus parses a NBSTAT node-status reply into its workstation name
// and unit-ID MAC. It skips the answer resource name (literal or compression
// pointer), validates the record type, and reads the names table and the unit ID
// within the declared RDLENGTH bounds; anything malformed yields empty fields.
func parseNBStatStatus(buf []byte) NetBIOSStatus {
	if len(buf) < 12 {
		return NetBIOSStatus{}
	}
	an := int(buf[6])<<8 | int(buf[7])
	if an < 1 {
		return NetBIOSStatus{}
	}
	off, ok := skipNBName(buf, 12)
	if !ok || off+10 > len(buf) {
		return NetBIOSStatus{}
	}
	rtype := int(buf[off])<<8 | int(buf[off+1])
	rdlen := int(buf[off+8])<<8 | int(buf[off+9])
	off += 10
	if rtype != nbstatType || rdlen < 1 || off+rdlen > len(buf) {
		return NetBIOSStatus{}
	}
	rdata := buf[off : off+rdlen]
	return NetBIOSStatus{Name: pickUniqueWorkstation(rdata), MAC: nbUnitIDMAC(rdata)}
}

// nbUnitIDMAC returns the unit ID that directly follows the names table (the
// first 6 bytes of the statistics block) as a canonical MAC, or "" when the table
// overruns the record, no full unit ID follows it, or the ID fails the same
// shape checks as an ARP entry (all-zero, group/broadcast, malformed).
func nbUnitIDMAC(rdata []byte) string {
	end := 1 + int(rdata[0])*nbNameEntryLen
	if end+6 > len(rdata) {
		return ""
	}
	u := rdata[end : end+6]
	mac, ok := normalizeMAC(fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", u[0], u[1], u[2], u[3], u[4], u[5]))
	if !ok {
		return ""
	}
	return mac
}

// skipNBName advances past a DNS/NetBIOS encoded name, returning the offset just
// after it. It handles literal labels and a terminal compression pointer, and is
// bounded against the buffer; any overrun returns ok=false.
func skipNBName(buf []byte, off int) (int, bool) {
	for {
		if off < 0 || off >= len(buf) {
			return 0, false
		}
		b := int(buf[off])
		switch {
		case b == 0x00:
			return off + 1, true
		case b&0xC0 == 0xC0: // compression pointer ends the name
			if off+2 > len(buf) {
				return 0, false
			}
			return off + 2, true
		case b&0xC0 == 0x00: // literal label
			off += 1 + b
			if off > len(buf) {
				return 0, false
			}
		default:
			return 0, false
		}
	}
}

// pickUniqueWorkstation scans a NBSTAT names table (a 1-byte count followed by
// fixed-width entries) for the <00>-suffix unique (non-group) workstation name.
// Every entry is bounds-checked; a short or malformed table yields "".
func pickUniqueWorkstation(rdata []byte) string {
	count := int(rdata[0])
	pos := 1
	for i := 0; i < count; i++ {
		if pos+nbNameEntryLen > len(rdata) {
			return "" // declared more names than the table holds
		}
		nameBytes := rdata[pos : pos+15]
		suffix := rdata[pos+15]
		flags := int(rdata[pos+16])<<8 | int(rdata[pos+17])
		pos += nbNameEntryLen
		if suffix == nbSuffixWorkstation && flags&nbFlagGroup == 0 {
			return sanitizeNetBIOSName(nameBytes)
		}
	}
	return ""
}

// sanitizeNetBIOSName trims the trailing space/null padding of a fixed-width
// NetBIOS name and passes it through the shared hostname sanitizer.
func sanitizeNetBIOSName(name []byte) string {
	return sanitizeHostname(strings.TrimRight(string(name), " \x00"))
}
