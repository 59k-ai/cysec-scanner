// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"os"
	"runtime"
	"testing"
)

func TestAuthorizers(t *testing.T) {
	admin := AdminAuthorizer(27)
	for _, c := range []struct {
		name string
		p    Peer
		ok   bool
	}{
		{"root", Peer{UID: 0, GID: 0}, true},
		{"adminGroup", Peer{UID: 1000, GID: 1000, Groups: []int{1000, 27}}, true},
		{"plainUser", Peer{UID: 1000, GID: 1000, Groups: []int{1000}}, false},
		{"windowsAdmin", Peer{UID: -1, GID: -1, SID: "S-1-5-21-1-2-3-500", Admin: true}, true},
		{"windowsSystem", Peer{UID: -1, GID: -1, SID: "S-1-5-18"}, true},
		{"windowsUser", Peer{UID: -1, GID: -1, SID: "S-1-5-21-1-2-3-1001"}, false},
		{"unknown", Peer{UID: -1, GID: -1}, false},
	} {
		err := admin.Authorize(c.p)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v, want ok=%v", c.name, err, c.ok)
		}
	}
	if err := AdminAuthorizer(-1).Authorize(Peer{UID: 1000, Groups: []int{-1}}); err == nil {
		t.Error("a negative admin gid matched")
	}

	same := SameUserAuthorizer()
	if runtime.GOOS == "windows" {
		sid, err := CurrentUserSID()
		if err != nil || sid == "" {
			t.Fatalf("CurrentUserSID: %q %v", sid, err)
		}
		if err := same.Authorize(Peer{UID: -1, GID: -1, SID: sid}); err != nil {
			t.Errorf("same SID refused: %v", err)
		}
		if err := same.Authorize(Peer{UID: -1, GID: -1, SID: "S-1-5-21-1-2-3-4"}); err == nil {
			t.Error("different SID accepted")
		}
	} else {
		if err := same.Authorize(Peer{UID: os.Geteuid(), GID: 0}); err != nil {
			t.Errorf("same uid refused: %v", err)
		}
		if err := same.Authorize(Peer{UID: os.Geteuid() + 1}); err == nil {
			t.Error("different uid accepted")
		}
		if err := same.Authorize(Peer{UID: -1}); err == nil {
			t.Error("unknown uid accepted")
		}
		if sid, err := CurrentUserSID(); sid != "" || err != nil {
			t.Errorf("CurrentUserSID off Windows: %q %v", sid, err)
		}
	}

	if AdminPipeSDDL != "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;0x0012019b;;;BA)" {
		t.Errorf("AdminPipeSDDL %q", AdminPipeSDDL)
	}
	if got := SameUserPipeSDDL("S-1-5-21-9"); got != "D:P(D;;GA;;;NU)(A;;GA;;;S-1-5-21-9)(A;;GA;;;SY)" {
		t.Errorf("SameUserPipeSDDL %q", got)
	}
}
