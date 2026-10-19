// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Command cysec-scanner is a thin CLI wrapper over the public scanner library.
// It translates its flag surface into a scanner.Config, drives scanner.Run, and
// serializes progress to NDJSON — it holds no scanning logic of its own.
//
// The engine<->wrapper contract (locked): stdout carries ONLY NDJSON progress
// events; the payload goes to --payload-out, never stdout; logs go to stderr;
// scope CIDRs arrive via argv. The engine opens no inbound socket and exposes no
// API of its own (ENG-04) — progress is stdout NDJSON only. The grep gate
// enforces that boundary.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/59k-ai/cysec-scanner/internal/portscan"
	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
	"github.com/59k-ai/cysec-scanner/scanner"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// cidrList is a repeatable --cidr flag accumulator.
type cidrList []string

func (c *cidrList) String() string { return strings.Join(*c, ",") }
func (c *cidrList) Set(v string) error {
	*c = append(*c, v)
	return nil
}

// run is the testable entrypoint: stdout is reserved for NDJSON events, stderr
// for logs. It returns the process exit code (0 ok, 2 usage error, 1 fatal,
// 130 on context cancellation).
func run(args []string, stdout, stderr io.Writer) int {
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	fs := flag.NewFlagSet("cysec-scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	payloadOut := fs.String("payload-out", "", "path to write the v6 payload JSON (required)")
	var cidrs cidrList
	fs.Var(&cidrs, "cidr", "scope CIDR to scan (repeatable); empty means auto-detect the local subnet")
	timing := fs.String("timing", "polite", "scan timing tier: polite (default)")
	ports := fs.String("ports", "", "comma-separated ports/ranges to scan, e.g. \"22,80,443,8000-8010\"; empty uses the curated default set")
	probeFragile := fs.Bool("probe-fragile", false, "probe fragile devices (printers/IoT/network gear) that are skipped from intrusive OS stack probing by default")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Validate the operator --ports list/ranges up front (D-02). An empty set is
	// left nil so scanner.Config falls back to the curated default port set.
	var resolvedPorts []int
	if *ports != "" {
		parsed, err := portscan.ParsePorts(*ports)
		if err != nil {
			logger.Error("invalid --ports value", "err", err)
			return 2
		}
		resolvedPorts = parsed
	}
	if *payloadOut == "" {
		logger.Error("missing required flag", "flag", "--payload-out")
		return 2
	}

	// One cancelable context threaded through Run (ENG-01). SIGINT/SIGTERM cancel
	// it so an interrupted run stops cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			logger.Warn("signal received, cancelling pipeline")
			cancel()
		case <-ctx.Done():
		}
	}()

	// The progress sink is a PURE NDJSON serializer: scanner.Run owns Seq/TS
	// (D-08); the sink marshals each already-populated Event to one stdout line
	// via the Emitter's atomic encode discipline (one JSON object per line, under
	// a mutex). stdout carries ONLY NDJSON; the payload goes to --payload-out.
	emitter := progress.NewEmitter(stdout)
	sink := func(ev progress.Event) {
		_ = emitter.Write(ev)
	}

	cfg := scanner.Config{
		CIDRs:        []string(cidrs),
		Timing:       *timing,
		Ports:        resolvedPorts,
		ProbeFragile: *probeFragile,
	}

	pl, runErr := scanner.Run(ctx, cfg, sink)
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			logger.Error("pipeline cancelled", "err", runErr)
			return 130
		}
		logger.Error("pipeline failed", "err", runErr)
		return 1
	}

	data, err := json.MarshalIndent(pl, "", "  ")
	if err != nil {
		logger.Error("payload marshal failed", "err", err)
		return 1
	}
	if err := os.WriteFile(*payloadOut, append(data, '\n'), 0o644); err != nil {
		logger.Error("payload write failed", "path", *payloadOut, "err", err)
		return 1
	}
	logger.Info("payload written", "path", *payloadOut, "schema_version", payload.SchemaVersion, "cidrs", len(cidrs))
	return 0
}
