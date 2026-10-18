// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Command cysec-scanner is the pure-Go evidence engine that runs behind the
// closed Collector wrapper. This Phase-2 skeleton (D-04) is a real
// compiled binary, not a mock: it runs the staged pipeline under one cancelable
// context, streams NDJSON ProgressEvents to stdout, logs to stderr via slog,
// assembles an empty-ish strict-valid v5 payload and writes it to the
// --payload-out file, then exits 0 on success / non-zero on a fatal error.
//
// The engine↔wrapper contract (locked, D): stdout carries ONLY NDJSON progress
// events; the payload goes to --payload-out, never stdout; logs go to stderr;
// credentials arrive via the child environment, scope CIDRs via argv. The engine
// opens no inbound socket and exposes no API of its own (ENG-04) — progress is
// stdout NDJSON only. The grep gate in 02-02 Task 3 enforces that boundary.
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

	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/discovery"
	"github.com/cysec-watch/cysec-scanner/internal/fingerprint"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/pipeline"
	"github.com/cysec-watch/cysec-scanner/internal/portscan"
	"github.com/cysec-watch/cysec-scanner/internal/progress"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// collectorVersion stamps the payload's collector_version field for this engine.
const collectorVersion = "cysec-scanner-engine/0.0.0"

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

	// Resolve the port set: the curated default when no --ports override is given,
	// otherwise the validated operator list/ranges (D-02). The resolved set rides
	// under the active timing tier's scan-wide PPS cap.
	resolvedPorts := portscan.DefaultPortSet
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

	// One cancelable context threaded through the whole pipeline (ENG-01).
	// SIGINT/SIGTERM cancel it so an interrupted run stops cleanly.
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

	// ENG-06: detect the runtime capabilities exactly once at startup and thread
	// the immutable value struct into the stages by value.
	caps := capabilities.Detect()

	// The shared accumulator the discovery stage writes assets into and later
	// stages enrich. Stage closures capture it, so the pipeline control-flow
	// package stays untouched (ENG-01).
	st := scanstate.New(string(fullPayloadType), collectorVersion)
	stages := []pipeline.Stage{
		{Name: pipeline.StageDiscovery, Run: func(ctx context.Context) error {
			return discovery.Run(ctx, st, caps, []string(cidrs))
		}},
		{Name: pipeline.StagePort, Run: func(ctx context.Context) error {
			return portscan.Run(ctx, st, caps, portscan.Options{Tier: portscan.ResolveTier(*timing), Ports: resolvedPorts})
		}},
		{Name: pipeline.StageFingerprint, Run: func(ctx context.Context) error {
			return fingerprint.Run(ctx, st, caps, fingerprint.Options{ProbeFragile: *probeFragile})
		}},
		{Name: pipeline.StageAuthPosture, Run: func(context.Context) error { return nil }},
	}

	emitter := progress.NewEmitter(stdout)
	_ = emitter.Phase(progress.PhaseStart, "collect")
	runErr := pipeline.NewWithStages(stages).Run(ctx, func(stage pipeline.StageName) {
		_ = emitter.Agent(progress.AgentStart, "collect", string(stage))
	})
	_ = emitter.Phase(progress.PhaseDone, "collect")

	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			logger.Error("pipeline cancelled", "err", runErr)
			return 130
		}
		logger.Error("pipeline failed", "err", runErr)
		return 1
	}

	// Snapshot the accumulated payload the stages populated.
	pl := st.Payload()
	// WR-02 — force every required container (top-level + nested) non-nil so a
	// populated asset from a scanning stage never marshals a required list/map
	// to JSON "null", which the strict reference schema 400-rejects.
	pl.Normalize()
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

// payloadKind is the engine's payload_type. "full" is the valid PayloadType
// enum member used for a complete assessment run.
type payloadKind string

const fullPayloadType payloadKind = "full"
