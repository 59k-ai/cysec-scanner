// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import "testing"

// TestParseProcNetARP pins the Linux /proc/net/arp parse: the header is skipped,
// the all-zero and the malformed hardware addresses are filtered, and a too-short
// line is skipped without a panic. Only the two well-formed rows survive.
func TestParseProcNetARP(t *testing.T) {
	const fixture = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.3      0x1         0x2         zz:zz:zz:zz:zz:zz     *        eth0
192.168.1.4      0x1         0x2         10:22:33:44:55:66     *        wlan0
garbage line too few
`
	got := parseProcNetARP(fixture)
	if len(got) != 2 {
		t.Fatalf("parsed %d entries, want 2: %v", len(got), got)
	}
	if got["192.168.1.1"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("192.168.1.1 -> %q, want aa:bb:cc:dd:ee:ff", got["192.168.1.1"])
	}
	if got["192.168.1.4"] != "10:22:33:44:55:66" {
		t.Errorf("192.168.1.4 -> %q, want 10:22:33:44:55:66", got["192.168.1.4"])
	}
	if _, ok := got["192.168.1.2"]; ok {
		t.Error("all-zero (unresolved) MAC must be filtered")
	}
	if _, ok := got["192.168.1.3"]; ok {
		t.Error("malformed MAC must be filtered")
	}
}

// TestParseProcNetARPEmpty proves a missing/empty cache parses to an empty map
// (never nil-deref, never panic) — the degraded path.
func TestParseProcNetARPEmpty(t *testing.T) {
	if got := parseProcNetARP(""); got == nil || len(got) != 0 {
		t.Fatalf("empty input -> %v, want empty map", got)
	}
}

// TestParseARPCommand pins the `arp -a` parse for both the BSD/macOS and the
// Windows line shapes, including the hyphen-separated Windows MAC form and an
// "(incomplete)" entry that must be skipped.
func TestParseARPCommand(t *testing.T) {
	const bsd = `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.9) at (incomplete) on en0 [ethernet]`
	got := parseARPCommand(bsd)
	if got["192.168.1.1"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("bsd 192.168.1.1 -> %q, want aa:bb:cc:dd:ee:ff", got["192.168.1.1"])
	}
	if _, ok := got["192.168.1.9"]; ok {
		t.Error("incomplete entry must be skipped")
	}

	const win = `  192.168.1.20         aa-bb-cc-dd-ee-00     dynamic`
	got2 := parseARPCommand(win)
	if got2["192.168.1.20"] != "aa:bb:cc:dd:ee:00" {
		t.Errorf("win 192.168.1.20 -> %q, want aa:bb:cc:dd:ee:00 (hyphen form normalised)", got2["192.168.1.20"])
	}
}

// TestParseARPCommandBSDUnpaddedOctets pins the macOS/BSD `arp -an` shape, which
// prints each octet without zero padding ("74:24:9f:6:c8:ff"). net.ParseMAC
// rejects one-digit groups, so without normalisation every MAC with an octet
// below 0x10 (about a third of all MACs) was silently dropped.
func TestParseARPCommandBSDUnpaddedOctets(t *testing.T) {
	const bsd = `? (192.168.1.37) at 74:24:9f:6:c8:ff on en0 ifscope [ethernet]
? (192.168.1.51) at 0:4b:c4:5:b6:6f on en0 ifscope [ethernet]
? (192.168.1.1) at 74:24:9f:96:90:57 on en0 ifscope [ethernet]`
	got := parseARPCommand(bsd)
	want := map[string]string{
		"192.168.1.37": "74:24:9f:06:c8:ff",
		"192.168.1.51": "00:4b:c4:05:b6:6f",
		"192.168.1.1":  "74:24:9f:96:90:57",
	}
	for ip, mac := range want {
		if got[ip] != mac {
			t.Errorf("%s -> %q, want %q", ip, got[ip], mac)
		}
	}
}

// TestParseARPCommandRejectsGroupMACs proves the broadcast and multicast entries a
// readable macOS cache always lists (192.168.1.255 at ff:ff:ff:ff:ff:ff, the mDNS
// group at 1:0:5e:0:0:fb) never become a host MAC. A neighbour's own address is
// unicast; a set I/G bit means the entry is not a device, and the broadcast
// address lies inside the scan scope, so trusting it would harvest a fake asset.
func TestParseARPCommandRejectsGroupMACs(t *testing.T) {
	const bsd = `? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.158) at 46:1e:9e:d5:20:a2 on en0 ifscope permanent [ethernet]`
	got := parseARPCommand(bsd)
	if len(got) != 1 || got["192.168.1.158"] != "46:1e:9e:d5:20:a2" {
		t.Fatalf("got %v, want only 192.168.1.158 -> 46:1e:9e:d5:20:a2", got)
	}
}

// TestARPCommandArgs pins the per-OS arp invocation. macOS/BSD `arp -a` reverse-
// resolves every entry; with a few hundred cached neighbours that took ~9 s and
// blew the 2 s read timeout, so a readable cache still yielded no MACs. -n skips
// the lookups. Windows arp has no lowercase -n (its -N takes an interface
// address), so it keeps plain -a.
func TestARPCommandArgs(t *testing.T) {
	cases := map[string][]string{
		"darwin":  {"-an"},
		"freebsd": {"-an"},
		"windows": {"-a"},
	}
	for goos, want := range cases {
		got := arpCommandArgs(goos)
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("arpCommandArgs(%q) = %v, want %v", goos, got, want)
		}
	}
}
