// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Command ipc-refhost is a reference host for the local IPC protocol. It
// serves the base host (status.get, run.start, run.cancel, events.subscribe)
// on one local endpoint and plays a scripted fake run instead of scanning, so
// IPC clients can be tested end to end against a real socket or named pipe.
//
// It is a test tool only: it admits only peers running as the same user,
// listens inside a directory the caller owns (or on a pipe whose DACL admits
// only the current user), never links the scan engine and is not installed by
// any package.
//
// Once listening it writes a fresh token to --token-file (mode 0600, written
// to a temporary file and renamed into place) and prints exactly one line,
// "READY <address>", to stdout. Logs go to stderr. It exits cleanly on
// SIGINT or SIGTERM and, with --exit-on-stdin-eof, when stdin is closed (the
// portable stop signal for harnesses on Windows). On exit it removes the
// token file and the socket.
//
// Usage:
//
//	go run ./tools/ipc-refhost --address /tmp/dir/host.sock --token-file /tmp/dir/token \
//	    [--script run.ndjson] [--step 50ms] [--autostart] [--exit-on-stdin-eof] [--name reference-host]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/59k-ai/cysec-scanner/ipc"
	"github.com/59k-ai/cysec-scanner/ipc/runstate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ipc-refhost", flag.ContinueOnError)
	fs.SetOutput(stderr)
	address := fs.String("address", "", "socket path (Unix) or \\\\.\\pipe\\ name (Windows); required")
	tokenFile := fs.String("token-file", "", "file that receives the session token; required")
	scriptPath := fs.String("script", "", "NDJSON file of progress events to play (default: a built-in short run)")
	step := fs.Duration("step", 50*time.Millisecond, "delay between scripted events")
	autostart := fs.Bool("autostart", false, "start a run at boot, as a scheduled run")
	exitOnEOF := fs.Bool("exit-on-stdin-eof", false, "exit when stdin is closed")
	name := fs.String("name", "reference-host", "server name announced in the hello result")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *address == "" || *tokenFile == "" {
		fmt.Fprintln(stderr, "ipc-refhost: --address and --token-file are required")
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	fail := func(what string, err error) int {
		log.Error("refhost.failed", "step", what, "error", err.Error())
		return 1
	}

	script := defaultScript()
	if *scriptPath != "" {
		s, err := loadScript(*scriptPath)
		if err != nil {
			return fail("script", err)
		}
		script = s
	}

	release, err := acquireLock(*address)
	if err != nil {
		return fail("lock", err)
	}
	defer release()
	lo, err := listenOptions(*address)
	if err != nil {
		return fail("listen", err)
	}
	l, err := ipc.Listen(lo)
	if err != nil {
		return fail("listen", err)
	}
	defer l.Close()

	token, err := ipc.NewToken("")
	if err != nil {
		return fail("token", err)
	}
	if err := writeToken(*tokenFile, token); err != nil {
		return fail("token", err)
	}
	defer os.Remove(*tokenFile)

	srv, err := ipc.NewServer(ipc.ServerOptions{
		Token:      func() string { return token },
		Identify:   l.Identify(),
		Authorizer: ipc.SameUserAuthorizer(),
		Name:       *name,
		Version:    "0",
		Logger:     log,
	})
	if err != nil {
		return fail("server", err)
	}
	hub := runstate.NewHub(runstate.HubOptions{})
	runs := newFakeRun(hub, script, *step)
	host, err := ipc.NewHost(ipc.HostOptions{Server: srv, Hub: hub, Runs: runs, Logger: log})
	if err != nil {
		return fail("host", err)
	}
	served := make(chan error, 1)
	go func() { served <- host.Serve(l) }()

	if *autostart {
		if _, err := runs.begin("schedule", nil); err != nil {
			return fail("autostart", err)
		}
	}
	fmt.Fprintf(stdout, "READY %s\n", *address)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	eof := make(chan struct{})
	if *exitOnEOF {
		go func() {
			_, _ = io.Copy(io.Discard, stdin)
			close(eof)
		}()
	}

	code := 0
	select {
	case <-sigs:
	case <-eof:
	case err := <-served:
		log.Error("refhost.failed", "step", "serve", "error", err.Error())
		code = 1
	}
	runs.stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := host.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		log.Warn("refhost.shutdown", "error", err.Error())
	}
	return code
}

// writeToken writes token to path with owner-only permissions, through a
// temporary file in the same directory so a reader never sees a partial or
// stale token.
func writeToken(path, token string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.WriteString(token); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
