// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import "testing"

func TestParseScopeToken(t *testing.T) {
	t.Parallel()
	ok := map[string]string{
		"192.0.2.5/24": "192.0.2.0/24",
		"192.0.2.7":    "192.0.2.7/32",
	}
	for in, want := range ok {
		p, good := ParseScopeToken(in)
		if !good || p.String() != want {
			t.Errorf("ParseScopeToken(%q) = %v,%v want %s,true", in, p, good, want)
		}
	}
	for _, in := range []string{"10.0.0.0/33", "fe80::/64", "abc", ""} {
		if _, good := ParseScopeToken(in); good {
			t.Errorf("ParseScopeToken(%q) ok=true, want false", in)
		}
	}
}
