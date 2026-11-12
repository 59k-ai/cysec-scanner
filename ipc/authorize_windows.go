// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import "golang.org/x/sys/windows"

// CurrentUserSID returns the token user SID of this process, for
// SameUserPipeSDDL.
func CurrentUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}

func sameUser(p Peer) bool {
	if p.SID == "" {
		return false
	}
	sid, err := CurrentUserSID()
	return err == nil && sid == p.SID
}
