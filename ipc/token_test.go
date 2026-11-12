// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

// TestNewToken pins the token shape: prefix plus 43 base64url characters that
// decode to 32 random bytes, unique across draws, and no token on a read error.
func TestNewToken(t *testing.T) {
	const prefix = "tok_"
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		tok, err := NewToken(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, prefix) {
			t.Fatalf("missing prefix: %q", tok)
		}
		body := strings.TrimPrefix(tok, prefix)
		if len(body) != 43 {
			t.Fatalf("body length %d, want 43", len(body))
		}
		raw, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil || len(raw) != 32 {
			t.Fatalf("body does not decode to 32 bytes: %v len=%d", err, len(raw))
		}
		if seen[tok] {
			t.Fatalf("duplicate token after %d draws", i)
		}
		seen[tok] = true
	}

	saved := randReader
	randReader = failingReader{}
	defer func() { randReader = saved }()
	tok, err := NewToken(prefix)
	if err == nil || tok != "" {
		t.Fatalf("failing reader: want error and empty token, got %q %v", tok, err)
	}
}

// TestTokenEqual pins the comparison, including that an unset expected token
// never matches.
func TestTokenEqual(t *testing.T) {
	a, err := NewToken("p_")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewToken("p_")
	if err != nil {
		t.Fatal(err)
	}
	if !TokenEqual(a, a) {
		t.Fatal("equal tokens compared unequal")
	}
	if TokenEqual(a, b) {
		t.Fatal("different tokens compared equal")
	}
	if TokenEqual("p_"+strings.Repeat("A", 43), "p_"+strings.Repeat("B", 43)) {
		t.Fatal("same prefix, different body compared equal")
	}
	if TokenEqual("", "") {
		t.Fatal("empty want must never match")
	}
	if TokenEqual(a, "") {
		t.Fatal("empty want must never match")
	}
}
