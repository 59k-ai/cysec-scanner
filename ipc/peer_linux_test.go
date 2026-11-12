// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxPeerGroups(t *testing.T) {
	t.Run("rawPeerGroups", func(t *testing.T) {
		requireRoot(t)
		base := shortDir(t)
		if err := os.Chmod(base, 0o755); err != nil {
			t.Fatal(err)
		}
		addr := filepath.Join(base, "s.sock")
		l, err := Listen(ListenOptions{Address: addr, Unix: UnixOptions{
			DirOwnerUID: 0, DirGID: -1, SocketGID: -1, SocketMode: 0o666,
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		// 256 is 00 01 00 00 in memory: a NUL-truncating read would lose it
		// and everything after it.
		want := []uint32{256, 4242, 70000}
		p := helperPeer(t, l, addr, &syscall.Credential{Uid: 65534, Gid: 65534, Groups: want})
		for _, g := range want {
			if !slices.Contains(p.Groups, int(g)) {
				t.Fatalf("groups %v miss %d", p.Groups, g)
			}
		}
	})

	t.Run("procFallback", func(t *testing.T) {
		old := peerGroupsFn
		peerGroupsFn = func(int) ([]int, error) { return nil, unix.ENOPROTOOPT }
		defer func() { peerGroupsFn = old }()

		addr := filepath.Join(shortDir(t), "s.sock")
		l, err := Listen(userOpts(addr))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if _, err := dialT(t, addr); err != nil {
			t.Fatal(err)
		}
		p, err := l.Identify()(acceptOne(t, l))
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		gs, _ := os.Getgroups()
		for _, g := range gs {
			if !slices.Contains(p.Groups, g) {
				t.Fatalf("fallback groups %v miss %d", p.Groups, g)
			}
		}
	})

	t.Run("procParse", func(t *testing.T) {
		status := "Name:\tx\nUid:\t1000\t1001\t1001\t1001\nGid:\t5\t5\t5\t5\nGroups:\t4 24 256 \n"
		gs, err := parseProcGroups([]byte(status), 1001)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(gs, []int{4, 24, 256}) {
			t.Fatalf("groups %v", gs)
		}
		if _, err := parseProcGroups([]byte(status), 1000); err == nil {
			t.Fatal("a uid mismatch was accepted")
		}
		if _, err := parseProcGroups([]byte("Uid:\t1\t1\t1\t1\n"), 1); err == nil {
			t.Fatal("a missing Groups line was accepted")
		}
		if gs, err := parseProcGroups([]byte("Uid:\t1\t1\t1\t1\nGroups:\n"), 1); err != nil || len(gs) != 0 {
			t.Fatalf("empty Groups line: %v %v", gs, err)
		}
	})
}
