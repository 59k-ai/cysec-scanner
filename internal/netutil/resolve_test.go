// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package netutil

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSanitizeHostname(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"trailing dot trimmed", "host.example.com.", "host.example.com"},
		{"surrounding space trimmed", "  spaced.host  ", "spaced.host"},
		{"control bytes stripped", "host\x00\x07\x1f.local.", "host.local"},
		{"del byte stripped", "ho\x7fst.local", "host.local"},
		{"all control collapses to empty", "\x01\x02\x03", ""},
		{"over-long is capped", strings.Repeat("a", 300), strings.Repeat("a", maxHostnameLen)},
		{"plain name untouched", "WORKSTATION", "WORKSTATION"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeHostname(c.in); got != c.want {
				t.Errorf("sanitizeHostname(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	orig := lookupAddr
	defer func() { lookupAddr = orig }()

	t.Run("hit returns first sanitized PTR", func(t *testing.T) {
		lookupAddr = func(context.Context, string) ([]string, error) {
			return []string{"myhost.example.com.", "second.example.com."}, nil
		}
		if got := ReverseDNS(context.Background(), "10.0.0.1", time.Second); got != "myhost.example.com" {
			t.Errorf("ReverseDNS hit = %q, want myhost.example.com", got)
		}
	})

	t.Run("error is a miss", func(t *testing.T) {
		lookupAddr = func(context.Context, string) ([]string, error) {
			return nil, errors.New("no such host")
		}
		if got := ReverseDNS(context.Background(), "10.0.0.1", time.Second); got != "" {
			t.Errorf("ReverseDNS error = %q, want \"\"", got)
		}
	})

	t.Run("empty result is a miss", func(t *testing.T) {
		lookupAddr = func(context.Context, string) ([]string, error) {
			return nil, nil
		}
		if got := ReverseDNS(context.Background(), "10.0.0.1", time.Second); got != "" {
			t.Errorf("ReverseDNS empty = %q, want \"\"", got)
		}
	})
}
