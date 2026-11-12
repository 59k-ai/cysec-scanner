// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// authorize.go holds the two stock peer policies and the pipe DACLs that go
// with them. Both policies decide on kernel-reported identity only (uid and
// groups, or the token SID and its enabled groups); Peer.User is a display
// name and never part of a decision.

import (
	"errors"
	"slices"
)

// AdminPipeSDDL is the DACL for a pipe that only LocalSystem and elevated
// administrators may open:
//
//   - P: protected, nothing is inherited;
//   - deny NU: network logons never get in;
//   - SY: full access;
//   - BA: 0x0012019b = FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA |
//     FILE_WRITE_ATTRIBUTES. That is FILE_GENERIC_WRITE without
//     FILE_APPEND_DATA, which on a pipe is FILE_CREATE_PIPE_INSTANCE, so an
//     administrator can talk to the server but cannot add a rogue instance.
//
// A non-elevated administrator carries BA as a deny-only SID, so this ACE
// does not match and the open is refused by the kernel.
const AdminPipeSDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;0x0012019b;;;BA)"

// localSystemSID is the well-known SID of LocalSystem.
const localSystemSID = "S-1-5-18"

// SameUserPipeSDDL returns a DACL that admits only the user sid and
// LocalSystem, for a host that serves its own user.
func SameUserPipeSDDL(sid string) string {
	return "D:P(D;;GA;;;NU)(A;;GA;;;" + sid + ")(A;;GA;;;SY)"
}

// ErrPeerNotAllowed is returned by the stock authorizers.
var ErrPeerNotAllowed = errors.New("ipc: peer not allowed")

// adminGroupFallback, when set, answers group membership for a peer whose
// kernel-reported group list may be truncated (macOS xucred).
var adminGroupFallback func(p Peer, gid int) bool

// AdminAuthorizer admits privileged principals only: uid 0 or a member of
// adminGID on Unix, LocalSystem or an elevated member of
// BUILTIN\Administrators on Windows (Peer.Admin, set by the pipe peer
// reader from the token's enabled groups). A negative adminGID disables the
// group rule.
func AdminAuthorizer(adminGID int) Authorizer {
	return AuthorizerFunc(func(p Peer) error {
		switch {
		case p.UID == 0, p.Admin, p.SID == localSystemSID:
			return nil
		case adminGID >= 0 && p.UID >= 0 && slices.Contains(p.Groups, adminGID):
			return nil
		case adminGID >= 0 && p.UID >= 0 && adminGroupFallback != nil && adminGroupFallback(p, adminGID):
			return nil
		}
		return ErrPeerNotAllowed
	})
}

// SameUserAuthorizer admits only peers running as the same user as this
// process: the effective uid on Unix, the token user SID on Windows.
func SameUserAuthorizer() Authorizer {
	return AuthorizerFunc(func(p Peer) error {
		if sameUser(p) {
			return nil
		}
		return ErrPeerNotAllowed
	})
}
