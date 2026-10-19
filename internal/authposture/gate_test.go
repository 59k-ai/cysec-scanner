// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"testing"

	"github.com/59k-ai/cysec-scanner/internal/payload"
)

// ptr is a generic pointer helper shared by the authposture tests.
func ptr[T any](v T) *T { return &v }

// svcPorts builds a service slice with the given open ports.
func svcPorts(ports ...int) []payload.ServiceItem {
	s := make([]payload.ServiceItem, 0, len(ports))
	for _, p := range ports {
		s = append(s, payload.ServiceItem{Port: p})
	}
	return s
}

// TestWindowsGated is the D-03 truth table. It MUST include a rejection row for a
// confident non-Windows guess with 445 open, and admit rows for os_guess
// unknown/nil with each Windows-indicative port open.
func TestWindowsGated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ai   payload.AssetItem
		want bool
	}{
		{"confident Windows guess admitted", payload.AssetItem{OSGuess: ptr("Windows")}, true},
		{"confident Windows guess admitted even with no Windows ports", payload.AssetItem{OSGuess: ptr("Windows"), Services: svcPorts(80)}, true},
		{"confident non-Windows Linux with 445 open REJECTED (D-03)", payload.AssetItem{OSGuess: ptr("Linux"), Services: svcPorts(445)}, false},
		{"unknown literal + 445 admitted", payload.AssetItem{OSGuess: ptr("unknown"), Services: svcPorts(445)}, true},
		{"unknown literal + 135 admitted", payload.AssetItem{OSGuess: ptr("unknown"), Services: svcPorts(135)}, true},
		{"unknown literal + 3389 admitted", payload.AssetItem{OSGuess: ptr("unknown"), Services: svcPorts(3389)}, true},
		{"nil guess + 445 admitted", payload.AssetItem{Services: svcPorts(445)}, true},
		{"nil guess + only non-Windows ports rejected", payload.AssetItem{Services: svcPorts(22, 80)}, false},
		{"nil guess + no ports rejected", payload.AssetItem{}, false},
		{"unknown literal + only non-Windows ports rejected", payload.AssetItem{OSGuess: ptr("unknown"), Services: svcPorts(22, 443)}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := windowsGated(tc.ai); got != tc.want {
				t.Fatalf("windowsGated = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClampWorkers covers the WINAD-04 boundary: 3->4, 4->4, 8->8, 9->8, 0->4,
// and confirms the package default sits inside [4,8].
func TestClampWorkers(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want int }{
		{3, 4}, {4, 4}, {8, 8}, {9, 8}, {0, 4}, {5, 5}, {100, 8}, {-7, 4},
	}
	for _, tc := range cases {
		if got := clampWorkers(tc.in); got != tc.want {
			t.Errorf("clampWorkers(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if defaultAuthWorkers < 4 || defaultAuthWorkers > 8 {
		t.Fatalf("defaultAuthWorkers %d outside [4,8]", defaultAuthWorkers)
	}
}
