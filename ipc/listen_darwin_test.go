// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"errors"
	"os"
	"slices"
	"testing"
)

// TestAncestorPolicyAcceptsVarRun runs the ancestor check against the real
// /var/run, which macOS ships as root:daemon 0775. The check only Lstats, so
// it needs no root, and a system socket directory such as
// /var/run/<service> must pass it with the built-in group trust.
func TestAncestorPolicyAcceptsVarRun(t *testing.T) {
	const dir = "/var/run/ipc-ancestor-test"
	if err := checkAncestors(dir, 0, trustedAncestorGIDs); err != nil {
		t.Fatalf("default policy refuses a directory under /var/run: %v", err)
	}
	fi, err := os.Stat("/var/run")
	if err != nil {
		t.Fatal(err)
	}
	// Negative control: with no trusted group the same path must be refused
	// while /var/run is group-writable, which proves the check ran.
	if fi.Mode().Perm()&0o020 != 0 && fi.Mode()&os.ModeSticky == 0 {
		if err := checkAncestors(dir, 0, func(string) []int { return nil }); !errors.Is(err, ErrUnsafeDir) {
			t.Fatalf("empty trust list under group-writable /var/run: %v, want ErrUnsafeDir", err)
		}
	} else {
		t.Logf("/var/run is %v here; negative control not applicable", fi.Mode())
	}
}

// TestDaemonGroupTrustIsScopedToVarRun: the daemon group is trusted on the
// system socket directory only, never on another root:daemon directory.
func TestDaemonGroupTrustIsScopedToVarRun(t *testing.T) {
	for _, p := range []string{"/var/run", "/private/var/run"} {
		if !slices.Contains(trustedAncestorGIDs(p), 1) {
			t.Errorf("%s: daemon group not trusted", p)
		}
	}
	for _, p := range []string{"/", "/var", "/private/var", "/private/var/db", "/var/run/x", "/Users", "/var/runx"} {
		if got := trustedAncestorGIDs(p); !slices.Equal(got, []int{0}) {
			t.Errorf("%s: trusted %v, want [0]", p, got)
		}
	}
}
