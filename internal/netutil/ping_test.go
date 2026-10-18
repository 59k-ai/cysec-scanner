// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"errors"
	"testing"
)

// TestPingResultLiveUsesExitStatusNotOutputLanguage pins CR-01: host liveness is
// decided by the ping process exit status, never by matching an English output
// substring. A live host on a German-locale collector (the DACH target market)
// must still be reported live.
func TestPingResultLiveUsesExitStatusNotOutputLanguage(t *testing.T) {
	// Zero exit status (nil error) with a localized stats line → still live.
	germanOut := []byte("PING host (10.0.0.1): 56 data bytes\n" +
		"--- host ping statistics ---\n" +
		"1 Pakete übertragen, 1 empfangen, 0% Paketverlust\n")
	if live, _ := pingResultLive(germanOut, nil); !live {
		t.Fatal("zero exit status with German-locale output must report live")
	}

	// Zero exit status with empty/quiet output → still live (liveness never
	// depends on the output text).
	if live, _ := pingResultLive(nil, nil); !live {
		t.Fatal("zero exit status with empty output must report live")
	}

	// Non-zero exit (the normal no-reply case) → not live, even when the output
	// happens to contain the old English "1 received" phrase.
	if live, _ := pingResultLive([]byte("1 packets transmitted, 1 received"), errors.New("exit status 1")); live {
		t.Fatal("non-zero exit status must report not live regardless of output text")
	}

	// An exec failure (binary missing / deadline) → not live, no panic.
	if live, ttl := pingResultLive(nil, errors.New("exec: \"ping\": executable file not found")); live || ttl != 0 {
		t.Fatalf("exec failure must be not-live with zero TTL, got live=%v ttl=%d", live, ttl)
	}
}

// TestParseReplyTTLBounded pins WR-02: the TTL parser caps the digit run so a
// long/overflowing or localized reply line cannot overflow int or crash, and the
// result always stays within the valid 0..255 TTL band (or collapses to 0).
func TestParseReplyTTLBounded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"absent", "no ttl field present here", 0},
		{"normal", "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.1 ms", 64},
		{"max_valid", "ttl=255", 255},
		{"over_ceiling_collapses", "ttl=300", 0},
		{"long_overflowing_run", "ttl=99999999999999999999999999999999", 0},
		{"localized_line_without_ttl", "1 Pakete übertragen, 1 empfangen", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseReplyTTL(tc.in)
			if got != tc.want {
				t.Fatalf("parseReplyTTL(%q) = %d, want %d", tc.in, got, tc.want)
			}
			if got < 0 || got > 255 {
				t.Fatalf("parseReplyTTL(%q) = %d is outside the valid 0..255 band", tc.in, got)
			}
		})
	}
}
