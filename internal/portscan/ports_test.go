// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"reflect"
	"testing"
)

// TestDefaultPortSetCount pins the curated default at exactly 37 ports. D-01's
// prose says "38", but the authoritative set enumerates 37 and no 38th port is
// invented.
func TestDefaultPortSetCount(t *testing.T) {
	if len(DefaultPortSet) != 37 {
		t.Fatalf("DefaultPortSet has %d ports, want exactly 37", len(DefaultPortSet))
	}
}

// TestParsePorts covers the single/range/dedup/sort/invalid cases of the --ports
// override parser (D-02).
func TestParsePorts(t *testing.T) {
	valid := []struct {
		name string
		spec string
		want []int
	}{
		{"single list", "22,80,443", []int{22, 80, 443}},
		{"range with dedup and sort", "8000-8002,22,22", []int{22, 8000, 8001, 8002}},
		{"whitespace tolerated", " 22 , 80 ", []int{22, 80}},
		{"single-port range", "443-443", []int{443}},
		{"boundary ports", "1,65535", []int{1, 65535}},
	}
	for _, tc := range valid {
		got, err := ParsePorts(tc.spec)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: ParsePorts(%q) = %v, want %v", tc.name, tc.spec, got, tc.want)
		}
	}

	invalid := []struct {
		name string
		spec string
	}{
		{"zero", "0"},
		{"too high", "70000"},
		{"inverted range", "90-80"},
		{"non-numeric", "abc"},
		{"empty", ""},
		{"empty token", "22,,80"},
		{"non-numeric range bound", "22-abc"},
	}
	for _, tc := range invalid {
		if _, err := ParsePorts(tc.spec); err == nil {
			t.Errorf("%s: ParsePorts(%q) returned nil error, want a descriptive error", tc.name, tc.spec)
		}
	}
}
