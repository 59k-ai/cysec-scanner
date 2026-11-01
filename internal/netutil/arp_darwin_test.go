// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package netutil

import (
	"bytes"
	"os"
	"testing"
)

// rtCapture is a root capture of sysctl {CTL_NET, PF_ROUTE, 0, AF_INET,
// NET_RT_FLAGS_PRIV, RTF_LLINFO} on macOS 27, cut to four whole messages and
// rewritten to documentation values (RFC 5737 192.0.2.x, RFC 7042
// 00:00:5e:00:53:xx): a resolved neighbour 192.0.2.1 at 00:00:5e:00:53:01, an
// incomplete 192.0.2.2, the subnet broadcast and the mDNS multicast group. An
// unprivileged process without the topology-observation entitlement gets zero
// bytes from the same call.
func rtCapture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/rt-llinfo-root.bin")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRouteARPCapture(t *testing.T) {
	got := parseRouteARP(rtCapture(t))
	if len(got) != 1 || got["192.0.2.1"] != "00:00:5e:00:53:01" {
		t.Fatalf("got %v, want only 192.0.2.1 -> 00:00:5e:00:53:01 (incomplete, broadcast, multicast dropped)", got)
	}
}

// The redaction placeholder macOS hands out instead of a real MAC must never be
// reported as a host's MAC.
func TestParseRouteARPRedactedPlaceholder(t *testing.T) {
	b := bytes.Replace(rtCapture(t), []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01},
		[]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}, 1)
	if got := parseRouteARP(b); len(got) != 0 {
		t.Fatalf("got %v, want empty for the 02:00:00:00:00:00 placeholder", got)
	}
}

func TestParseRouteARPEmptyAndGarbage(t *testing.T) {
	if got := parseRouteARP(nil); got == nil || len(got) != 0 {
		t.Fatalf("empty dump -> %v, want empty map", got)
	}
	garbage := []byte{0xff, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}
	if got := parseRouteARP(garbage); len(got) != 0 {
		t.Fatalf("garbage -> %v, want empty map", got)
	}
	trunc := rtCapture(t)
	if got := parseRouteARP(trunc[:len(trunc)-7]); got == nil {
		t.Fatal("truncated dump must not yield nil")
	}
}

// ARPTable prefers the in-process sysctl (which an entitled engine can read
// without root, and a spawned arp cannot inherit) and falls back to arp -an.
func TestARPTableDarwinSourceOrder(t *testing.T) {
	origFetch, origCmd := fetchLLInfo, arpCommandOutput
	defer func() { fetchLLInfo, arpCommandOutput = origFetch, origCmd }()

	cap := rtCapture(t)
	fetchLLInfo = func() ([]byte, error) { return cap, nil }
	cmdCalled := false
	arpCommandOutput = func() ([]byte, error) {
		cmdCalled = true
		return []byte("? (192.0.2.7) at 0:0:5e:0:53:7 on en0 ifscope [ethernet]\n"), nil
	}
	if got := ARPTable(); got["192.0.2.1"] != "00:00:5e:00:53:01" || cmdCalled {
		t.Fatalf("sysctl path: got %v (arp called=%v), want the sysctl table without arp", got, cmdCalled)
	}

	fetchLLInfo = func() ([]byte, error) { return nil, nil } // hidden: zero bytes
	if got := ARPTable(); got["192.0.2.7"] != "00:00:5e:00:53:07" {
		t.Fatalf("fallback path: got %v, want the arp -an table", got)
	}
}
