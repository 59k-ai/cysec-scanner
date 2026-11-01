// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"testing"
)

// pad15 right-pads a NetBIOS name to the 15-byte name field with spaces.
func pad15(s string) []byte {
	b := make([]byte, 15)
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
	return b
}

// nbReply builds a NBSTAT node-status reply carrying the given names table.
func nbReply(rdata []byte) []byte {
	msg := []byte{
		0x00, 0x00, // id
		0x84, 0x00, // flags: response
		0x00, 0x00, // QDCOUNT
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	// Answer name: 0x20 + 32 encoded + root; type NBSTAT; class IN; ttl; rdlen.
	msg = append(msg, 0x20)
	msg = append(msg, encodeNetBIOSWildcard()...)
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

func TestNBStatParse(t *testing.T) {
	t.Run("returns the <00> unique workstation name, skipping a group name", func(t *testing.T) {
		var rd []byte
		rd = append(rd, 0x02) // two names
		// Group name with a <00> suffix must be skipped (group bit set).
		rd = append(rd, pad15("WORKGROUP")...)
		rd = append(rd, 0x00)       // suffix <00>
		rd = append(rd, 0x80, 0x00) // flags: group
		// Unique workstation name with a <00> suffix is the answer.
		rd = append(rd, pad15("WORKSTATION")...)
		rd = append(rd, 0x00)       // suffix <00>
		rd = append(rd, 0x00, 0x00) // flags: unique
		// Trailing statistics block (MAC etc.) is ignored.
		rd = append(rd, make([]byte, 46)...)

		if got := parseNBStatReply(nbReply(rd)); got != "WORKSTATION" {
			t.Errorf("NBSTAT parse = %q, want WORKSTATION", got)
		}
	})

	t.Run("no unique <00> name yields empty", func(t *testing.T) {
		var rd []byte
		rd = append(rd, 0x01)
		rd = append(rd, pad15("SERVICE")...)
		rd = append(rd, 0x20)       // a service suffix, not <00>
		rd = append(rd, 0x00, 0x00) // unique
		if got := parseNBStatReply(nbReply(rd)); got != "" {
			t.Errorf("no workstation name parse = %q, want \"\"", got)
		}
	})

	t.Run("declared count larger than table collapses to empty", func(t *testing.T) {
		rd := []byte{0x05} // claims 5 names, provides none
		if got := parseNBStatReply(nbReply(rd)); got != "" {
			t.Errorf("over-declared count parse = %q, want \"\"", got)
		}
	})

	t.Run("truncated rdata collapses to empty", func(t *testing.T) {
		// Header says 1 answer; cut the message off inside the answer name.
		msg := []byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x41}
		if got := parseNBStatReply(msg); got != "" {
			t.Errorf("truncated parse = %q, want \"\"", got)
		}
	})

	t.Run("no answers yields empty", func(t *testing.T) {
		msg := []byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if got := parseNBStatReply(msg); got != "" {
			t.Errorf("no-answer parse = %q, want \"\"", got)
		}
	})
}

// nbTable builds a names table with one unique <00> workstation name followed by
// the given statistics block (whose first 6 bytes are the unit ID).
func nbTable(name string, stats []byte) []byte {
	rd := []byte{0x01}
	rd = append(rd, pad15(name)...)
	rd = append(rd, 0x00)       // suffix <00>
	rd = append(rd, 0x00, 0x00) // flags: unique
	return append(rd, stats...)
}

// stats46 returns a 46-byte NBSTAT statistics block starting with unit id.
func stats46(unit ...byte) []byte {
	b := make([]byte, 46)
	copy(b, unit)
	return b
}

// TestNBStatUnitID pins the node-status unit ID (the 6 bytes after the names
// table) as a MAC source: a Windows host reports its adapter MAC there. The value
// is self-reported by the host, so it is shape-validated like an ARP entry: the
// all-zero ID (Samba's usual answer), group (broadcast/multicast) IDs and a
// statistics block too short to hold an ID yield no MAC, without affecting the
// name.
func TestNBStatUnitID(t *testing.T) {
	cases := []struct {
		name    string
		rdata   []byte
		wantNm  string
		wantMAC string
	}{
		{"windows unit id", nbTable("WORKSTATION", stats46(0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e)),
			"WORKSTATION", "00:1a:2b:3c:4d:5e"},
		{"samba all-zero unit id", nbTable("NAS", stats46()), "NAS", ""},
		{"broadcast unit id", nbTable("X", stats46(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), "X", ""},
		{"multicast unit id", nbTable("X", stats46(0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb)), "X", ""},
		{"stats too short for a unit id", nbTable("SHORT", []byte{0x00, 0x1a, 0x2b}), "SHORT", ""},
		{"no stats block", nbTable("BARE", nil), "BARE", ""},
	}
	for _, c := range cases {
		got := parseNBStatStatus(nbReply(c.rdata))
		if got.Name != c.wantNm || got.MAC != c.wantMAC {
			t.Errorf("%s: got {%q %q}, want {%q %q}", c.name, got.Name, got.MAC, c.wantNm, c.wantMAC)
		}
	}

	// A names table that declares more entries than it holds is malformed: no
	// name and no unit id are trusted.
	bad := []byte{0x03}
	bad = append(bad, pad15("ONE")...)
	bad = append(bad, 0x00, 0x00, 0x00)
	if got := parseNBStatStatus(nbReply(bad)); got.MAC != "" {
		t.Errorf("overrunning table: MAC = %q, want empty", got.MAC)
	}
	if got := parseNBStatStatus([]byte{0x00}); got != (NetBIOSStatus{}) {
		t.Errorf("truncated reply: got %+v, want zero", got)
	}
}
