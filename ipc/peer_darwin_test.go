// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestPeerAdminGroup(t *testing.T) {
	const adminGID = 80

	t.Run("live", func(t *testing.T) {
		out, err := exec.Command("/usr/bin/id", "-G").Output()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(strings.Fields(string(out)), strconv.Itoa(adminGID)) {
			t.Skip("the test user is not in the admin group")
		}
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
			t.Fatal(err)
		}
		if len(p.Groups) > xucredMaxGroups {
			t.Fatalf("%d groups exceed the xucred cap", len(p.Groups))
		}
		if err := AdminAuthorizer(adminGID).Authorize(p); err != nil {
			t.Fatalf("AdminAuthorizer refused an admin: %v", err)
		}
	})

	t.Run("dsmemberutilFallback", func(t *testing.T) {
		// xucred carries at most 16 groups, so a full list without the
		// admin gid may simply be truncated.
		full := Peer{UID: 501, GID: 20, PID: 1}
		for g := 1000; len(full.Groups) < xucredMaxGroups; g++ {
			full.Groups = append(full.Groups, g)
		}
		short := Peer{UID: 501, GID: 20, PID: 1, Groups: []int{20, 12}}

		var calls []string
		reply, replyErr := "", error(nil)
		old := dsMemberCheck
		dsMemberCheck = func(_ context.Context, uid, gid int) (string, error) {
			calls = append(calls, strconv.Itoa(uid)+":"+strconv.Itoa(gid))
			return reply, replyErr
		}
		defer func() { dsMemberCheck = old }()

		reply = "user is a member of the group\n"
		if err := AdminAuthorizer(adminGID).Authorize(full); err != nil {
			t.Fatalf("member per dsmemberutil refused: %v", err)
		}
		if !slices.Equal(calls, []string{"501:80"}) {
			t.Fatalf("calls %v", calls)
		}

		reply = "user is not a member of the group\n"
		if err := AdminAuthorizer(adminGID).Authorize(full); err == nil {
			t.Fatal("non-member accepted")
		}
		reply = "user is a member of the group (maybe)\n"
		if err := AdminAuthorizer(adminGID).Authorize(full); err == nil {
			t.Fatal("inexact output accepted")
		}
		reply, replyErr = "user is a member of the group\n", errors.New("exit 1")
		if err := AdminAuthorizer(adminGID).Authorize(full); err == nil {
			t.Fatal("failed command accepted")
		}

		calls = nil
		replyErr = nil
		if err := AdminAuthorizer(adminGID).Authorize(short); err == nil {
			t.Fatal("short group list without admin accepted")
		}
		if len(calls) != 0 {
			t.Fatal("dsmemberutil consulted for an untruncated list")
		}
	})

	t.Run("dsmemberutilReal", func(t *testing.T) {
		if _, err := os.Stat(dsmemberutilPath); err != nil {
			t.Skip("dsmemberutil not present")
		}
		out, err := exec.Command("/usr/bin/id", "-G").Output()
		if err != nil {
			t.Fatal(err)
		}
		member := slices.Contains(strings.Fields(string(out)), strconv.Itoa(adminGID))
		reply, err := dsMemberCheck(context.Background(), os.Getuid(), adminGID)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(reply) == dsMemberYes; got != member {
			t.Fatalf("dsmemberutil says %q, id -G membership %v", reply, member)
		}
	})
}
