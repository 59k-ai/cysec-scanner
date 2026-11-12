// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
)

// tokenBytes is the token entropy: 256 bits.
const tokenBytes = 32

// randReader is the entropy source. It is a variable only so a test can prove
// that a failed read yields no token.
var randReader io.Reader = rand.Reader

// NewToken mints a capability token: prefix followed by 32 random bytes in
// unpadded base64url. The prefix is the host's choice, so leak scanners can
// recognise its tokens; this package adds none of its own.
func NewToken(prefix string) (string, error) {
	var raw [tokenBytes]byte
	if _, err := io.ReadFull(randReader, raw[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// TokenEqual reports whether got matches want in constant time. Both sides
// are hashed first so the comparison time does not depend on their lengths.
// An empty want never matches: a host that has not minted a token yet must
// not accept an empty one.
func TokenEqual(got, want string) bool {
	if want == "" {
		return false
	}
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}
