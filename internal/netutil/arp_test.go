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
192.168.1.4      0x1         0x2         11:22:33:44:55:66     *        wlan0
garbage line too few
`
	got := parseProcNetARP(fixture)
	if len(got) != 2 {
		t.Fatalf("parsed %d entries, want 2: %v", len(got), got)
	}
	if got["192.168.1.1"] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("192.168.1.1 -> %q, want aa:bb:cc:dd:ee:ff", got["192.168.1.1"])
	}
	if got["192.168.1.4"] != "11:22:33:44:55:66" {
		t.Errorf("192.168.1.4 -> %q, want 11:22:33:44:55:66", got["192.168.1.4"])
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
