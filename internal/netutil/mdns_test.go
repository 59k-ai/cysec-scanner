package netutil

import (
	"testing"
	"time"
)

// encodeDNSName encodes a dotted name as length-prefixed labels + root byte.
func encodeDNSName(name string) []byte {
	var b []byte
	for _, label := range splitNonEmpty(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0x00)
}

func splitNonEmpty(name string) []string {
	var out []string
	for _, l := range splitDots(name) {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// dnsHeader builds a 12-byte DNS header with the given section counts.
func dnsHeader(qd, an, ns, ar int) []byte {
	return []byte{
		0x00, 0x00, // id
		0x84, 0x00, // flags: response, authoritative
		byte(qd >> 8), byte(qd),
		byte(an >> 8), byte(an),
		byte(ns >> 8), byte(ns),
		byte(ar >> 8), byte(ar),
	}
}

func TestMDNSParse(t *testing.T) {
	t.Run("valid PTR reply yields the hostname", func(t *testing.T) {
		msg := dnsHeader(1, 1, 0, 0)
		q := encodeDNSName("1.0.0.10.in-addr.arpa")
		msg = append(msg, q...)
		msg = append(msg, 0x00, 0x0C, 0x00, 0x01) // QTYPE PTR, QCLASS IN
		// Answer: literal owner name, PTR, IN, ttl, rdlen, rdata=myhost.local
		msg = append(msg, encodeDNSName("1.0.0.10.in-addr.arpa")...)
		msg = append(msg, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78) // PTR IN ttl=120
		rdata := encodeDNSName("myhost.local")
		msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
		msg = append(msg, rdata...)

		if got := parseDNSHostname(msg); got != "myhost.local" {
			t.Errorf("valid PTR parse = %q, want myhost.local", got)
		}
	})

	t.Run("compression-pointer loop collapses to empty and terminates", func(t *testing.T) {
		// One answer whose name is a pointer to offset 12 (itself): the loop
		// guard must reject it rather than spin forever.
		msg := dnsHeader(0, 1, 0, 0) // header is 12 bytes; name starts at offset 12
		msg = append(msg, 0xC0, 0x0C) // pointer -> offset 12 (self)
		msg = append(msg, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

		done := make(chan string, 1)
		go func() { done <- parseDNSHostname(msg) }()
		select {
		case got := <-done:
			if got != "" {
				t.Errorf("compression loop parse = %q, want \"\"", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("parseDNSHostname did not terminate on a compression-pointer loop")
		}
	})

	t.Run("truncated rdata collapses to empty without over-reading", func(t *testing.T) {
		msg := dnsHeader(0, 1, 0, 0)
		msg = append(msg, encodeDNSName("x.local")...)
		// PTR, IN, ttl, rdlen=100 but no rdata bytes follow.
		msg = append(msg, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64)
		if got := parseDNSHostname(msg); got != "" {
			t.Errorf("truncated parse = %q, want \"\"", got)
		}
	})

	t.Run("label running past the buffer collapses to empty", func(t *testing.T) {
		msg := dnsHeader(0, 1, 0, 0)
		msg = append(msg, 0x3F) // label length 63 with no following bytes
		if got := parseDNSHostname(msg); got != "" {
			t.Errorf("overrun label parse = %q, want \"\"", got)
		}
	})

	t.Run("short buffer is a miss", func(t *testing.T) {
		if got := parseDNSHostname([]byte{0x00, 0x01, 0x02}); got != "" {
			t.Errorf("short buffer parse = %q, want \"\"", got)
		}
	})

	t.Run("valid compression pointer is followed correctly", func(t *testing.T) {
		// Question name at offset 12; the answer uses a pointer back to it. The
		// PTR rdata is a literal name. Proves forward progress works, not just
		// the loop rejection.
		msg := dnsHeader(1, 1, 0, 0)
		msg = append(msg, encodeDNSName("host.local")...) // question owner at off 12
		msg = append(msg, 0x00, 0x0C, 0x00, 0x01)         // QTYPE PTR, QCLASS IN
		msg = append(msg, 0xC0, 0x0C)                      // answer name -> offset 12
		msg = append(msg, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78)
		rdata := encodeDNSName("resolved.local")
		msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
		msg = append(msg, rdata...)
		if got := parseDNSHostname(msg); got != "resolved.local" {
			t.Errorf("valid pointer parse = %q, want resolved.local", got)
		}
	})
}
