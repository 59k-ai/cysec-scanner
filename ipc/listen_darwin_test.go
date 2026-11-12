// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"errors"
	"os"
	"testing"
)

// TestAncestorPolicyAcceptsVarRun runs the ancestor check against the real
// /var/run, which macOS ships as root:daemon 0775. The check only Lstats, so
// it needs no root, and a system socket directory such as
// /var/run/<service> must pass it with the default group trust.
func TestAncestorPolicyAcceptsVarRun(t *testing.T) {
	const dir = "/var/run/ipc-ancestor-test"
	if err := checkAncestors(dir, 0, defaultTrustedAncestorGIDs()); err != nil {
		t.Fatalf("default policy refuses a directory under /var/run: %v", err)
	}
	fi, err := os.Stat("/var/run")
	if err != nil {
		t.Fatal(err)
	}
	// Negative control: with no trusted group the same path must be refused
	// while /var/run is group-writable, which proves the check ran.
	if fi.Mode().Perm()&0o020 != 0 && fi.Mode()&os.ModeSticky == 0 {
		if err := checkAncestors(dir, 0, []int{}); !errors.Is(err, ErrUnsafeDir) {
			t.Fatalf("empty trust list under group-writable /var/run: %v, want ErrUnsafeDir", err)
		}
	} else {
		t.Logf("/var/run is %v here; negative control not applicable", fi.Mode())
	}
}
