// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ipc

import "os"

// CurrentUserSID returns "" off Windows, where peers are named by uid.
func CurrentUserSID() (string, error) { return "", nil }

func sameUser(p Peer) bool {
	return p.UID >= 0 && p.UID == os.Geteuid()
}
