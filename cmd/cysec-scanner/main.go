// Command cysec-scanner is the pure-Go evidence engine that runs behind the
// closed cysec-collector wrapper. This Phase-2 skeleton (D-04) is a real
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

	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/pipeline"
	"github.com/cysec-watch/cysec-scanner/internal/progress"
)

// collectorVersion stamps the payload's collector_version field for this engine.
const collectorVersion = "cysec-scanner-engine/0.0.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// cidrList is a repeatable --cidr flag accumulator.
type cidrList []string

func (c *cidrList) String() string  { return strings.Join(*c, ",") }
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
	payloadOut := fs.String("payload-out", "", "path to write the v5 payload JSON (required)")
	var cidrs cidrList
	fs.Var(&cidrs, "cidr", "scope CIDR to scan (repeatable); empty means auto-detect the local subnet")
	if err := fs.Parse(args); err != nil {
		return 2
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

	emitter := progress.NewEmitter(stdout)
	_ = emitter.Phase(progress.PhaseStart, "collect")
	runErr := pipeline.New().Run(ctx, func(stage pipeline.StageName) {
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

	// Assemble the empty-ish strict-valid v5 payload and write it to the file.
	// Real scanning stages will populate it from Phase 3 onward.
	pl := payload.NewEmpty(string(fullPayloadType), collectorVersion)
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
