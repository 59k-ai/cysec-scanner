// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package ipc

// peer_windows.go reads the identity of a named-pipe client from its token.
//
// The server impersonates the client (at identification level, as Dial
// requests), opens the thread token and reverts. The server must already
// have read from the pipe: impersonation uses the security context of the
// last message read. All of it runs on a goroutine locked to its OS thread,
// so the impersonation never leaks onto a thread the scheduler reuses. If
// RevertToSelf fails the goroutine returns WITHOUT UnlockOSThread: the
// runtime then terminates that thread instead of handing an impersonating
// thread to other goroutines.
//
// Admin is CheckTokenMembership for BUILTIN\Administrators, which counts
// enabled SIDs only; in a UAC-filtered token that SID is deny-only, so a
// non-elevated administrator is not an admin here. LocalSystem is admin too.

import (
	"errors"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/windows"
)

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// impersonationHooks are the thread-sensitive calls; tests replace them.
var impersonationHooks = struct {
	lock, unlock func()
	impersonate  func(windows.Handle) error
	openToken    func(*windows.Token) error
	revert       func() error
}{
	lock:        runtime.LockOSThread,
	unlock:      runtime.UnlockOSThread,
	impersonate: impersonateNamedPipeClient,
	openToken: func(tok *windows.Token) error {
		// openAsSelf: an identification-level token cannot be used to
		// open its own thread token, the access check runs as the server.
		return windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, tok)
	},
	revert: windows.RevertToSelf,
}

func impersonateNamedPipeClient(h windows.Handle) error {
	if err := procImpersonateNamedPipeClient.Find(); err != nil {
		return err
	}
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		if e == nil || errors.Is(e, windows.ERROR_SUCCESS) {
			return errors.New("ImpersonateNamedPipeClient failed")
		}
		return e
	}
	return nil
}

type tokenResult struct {
	tok windows.Token
	err error
}

// clientToken returns the pipe client's token, opened while impersonating.
func clientToken(h windows.Handle) (windows.Token, error) {
	ch := make(chan tokenResult, 1)
	go func() {
		hk := impersonationHooks
		hk.lock()
		if err := hk.impersonate(h); err != nil {
			hk.unlock()
			ch <- tokenResult{err: fmt.Errorf("ipc: impersonate pipe client: %w", err)}
			return
		}
		var tok windows.Token
		terr := hk.openToken(&tok)
		if rerr := hk.revert(); rerr != nil {
			if terr == nil {
				_ = tok.Close()
			}
			// Deliberately no unlock: this thread may still impersonate.
			ch <- tokenResult{err: fmt.Errorf("ipc: revert impersonation: %w", rerr)}
			return
		}
		hk.unlock()
		if terr != nil {
			ch <- tokenResult{err: fmt.Errorf("ipc: open client token: %w", terr)}
			return
		}
		ch <- tokenResult{tok: tok}
	}()
	r := <-ch
	return r.tok, r.err
}

func identifyPeer(c net.Conn) (Peer, error) {
	p, _, err := identifyPeerMembership(c)
	return p, err
}

// identifyPeerMembership is identifyPeer that also reports the raw
// BUILTIN\Administrators membership of the client token. Peer.Admin folds
// LocalSystem in by its user SID, which hides the membership result for a
// LocalSystem client; tests observe it here.
func identifyPeerMembership(c net.Conn) (Peer, bool, error) {
	p := Peer{UID: -1, GID: -1}
	fc, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return p, false, fmt.Errorf("ipc: %T has no pipe handle", c)
	}
	h := windows.Handle(fc.Fd())
	tok, err := clientToken(h)
	if err != nil {
		return p, false, err
	}
	defer tok.Close()

	tu, err := tok.GetTokenUser()
	if err != nil {
		return p, false, fmt.Errorf("ipc: client token user: %w", err)
	}
	p.SID = tu.User.Sid.String()
	ba, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return p, false, err
	}
	member, err := tok.IsMember(ba)
	if err != nil {
		return p, false, fmt.Errorf("ipc: client group check: %w", err)
	}
	p.Admin = member || p.SID == localSystemSID
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return p, false, fmt.Errorf("ipc: client pid: %w", err)
	}
	p.PID = int(pid)
	return p, member, nil
}
