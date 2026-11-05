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
//
// Opt-in surfaces (D-26). Without them the CLI behaves exactly as before and its
// stdout is the legacy five-kind NDJSON stream the Python engine driver reads:
//
//   - --events=detailed adds the detailed kinds (scan_start, stage_progress,
//     host, log, scan_end) to the stream; --events=legacy is the default.
//   - --cancel-on-stdin-eof cancels the scan cooperatively when stdin reaches
//     EOF. It is the portable cancel channel for parents that cannot deliver
//     SIGINT (Windows, D-27); without the flag stdin is never read, so
//     "</dev/null" callers are not cancelled by accident.
//   - On cancel (stdin EOF or SIGINT/SIGTERM) the partial payload is still
//     written to --payload-out, marked scan_status "cancelled" (D-25), and the
//     exit code stays 130 so no caller mistakes it for an upload-worthy run.
//   - --describe prints one JSON document describing the engine (version,
//     capabilities, local LAN networks with interface names, default ports,
//     timing tiers, event modes) and exits 0; --payload-out is not needed.
//   - --version prints the build version and exits 0.
//
// stdout therefore carries NDJSON only in scan mode and exactly one JSON
// document in --describe mode.
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
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/netutil"
	"github.com/59k-ai/cysec-scanner/internal/portscan"
	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
	"github.com/59k-ai/cysec-scanner/scanner"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// version is stamped by release tooling via -ldflags "-X main.version=<tag>".
// There is no in-tree version constant (README "Versioning convention").
var version = ""

// engineVersion resolves the reported version: the ldflags stamp, else the
// module version from the build info, else a short VCS revision, else "(devel)".
func engineVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
			return rev
		}
	}
	return "(devel)"
}

// describeCapabilities mirrors capabilities.Capabilities with the snake_case
// keys the GUI's strict --describe decoder expects.
type describeCapabilities struct {
	UnprivilegedICMP bool `json:"unprivileged_icmp"`
	SystemPing       bool `json:"system_ping"`
	ARPCache         bool `json:"arp_cache"`
}

// describeDoc is the single --describe document (SGUI-02): the one source of
// truth for subnet auto-detect, interfaces, default ports and tiers.
type describeDoc struct {
	EngineVersion string               `json:"engine_version"`
	Capabilities  describeCapabilities `json:"capabilities"`
	Networks      []netutil.LANNetwork `json:"networks"`
	DefaultPorts  []int                `json:"default_ports"`
	TimingTiers   []string             `json:"timing_tiers"`
	EventModes    []string             `json:"event_modes"`
}

func writeDescribe(stdout io.Writer) error {
	caps := capabilities.Detect()
	nets := netutil.LocalLANInterfaces()
	if nets == nil {
		nets = []netutil.LANNetwork{}
	}
	doc := describeDoc{
		EngineVersion: engineVersion(),
		Capabilities: describeCapabilities{
			UnprivilegedICMP: caps.UnprivilegedICMP,
			SystemPing:       caps.SystemPing,
			ARPCache:         caps.ARPCache,
		},
		Networks:     nets,
		DefaultPorts: portscan.DefaultPortSet,
		// Only the CLI-documented tier is advertised (D-12).
		TimingTiers: []string{"polite"},
		EventModes:  []string{"legacy", "detailed"},
	}
	return json.NewEncoder(stdout).Encode(doc)
}

// writePayload marshals pl and writes it to path with a trailing newline.
//
// The payload holds network inventory and posture evidence, so the file is
// owner-only (0600). The explicit Chmod tightens a pre-existing looser file,
// which the OpenFile mode alone does not touch (it only applies on create).
// On Windows Chmod(0o600) only keeps the file writable, which is harmless.
func writePayload(path string, pl payload.Payload) error {
	data, err := json.MarshalIndent(pl, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
// 130 on context cancellation). stdin is only read with --cancel-on-stdin-eof.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	fs := flag.NewFlagSet("cysec-scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	payloadOut := fs.String("payload-out", "", "path to write the v8 payload JSON (required in scan mode)")
	var cidrs cidrList
	fs.Var(&cidrs, "cidr", "scope CIDR to scan (repeatable); empty means auto-detect the local subnet")
	timing := fs.String("timing", "polite", "scan timing tier: polite (default)")
	ports := fs.String("ports", "", "comma-separated ports/ranges to scan, e.g. \"22,80,443,8000-8010\"; empty uses the curated default set")
	probeFragile := fs.Bool("probe-fragile", false, "probe fragile devices (printers/IoT/network gear) that are skipped from intrusive OS stack probing by default")
	events := fs.String("events", "legacy", "progress event mode on stdout: legacy (default) or detailed")
	cancelOnStdinEOF := fs.Bool("cancel-on-stdin-eof", false, "cancel the scan cooperatively when stdin reaches EOF (portable cancel channel)")
	describe := fs.Bool("describe", false, "print one JSON document describing the engine and exit")
	showVersion := fs.Bool("version", false, "print the engine version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Informational modes run before any scan-mode validation, so they need no
	// --payload-out.
	if *showVersion {
		if _, err := io.WriteString(stdout, engineVersion()+"\n"); err != nil {
			return 1
		}
		return 0
	}
	if *describe {
		if err := writeDescribe(stdout); err != nil {
			logger.Error("describe failed", "err", err)
			return 1
		}
		return 0
	}

	switch *events {
	case "legacy", "detailed":
	default:
		logger.Error("invalid --events value", "value", *events, "want", "legacy|detailed")
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
	// Portable cooperative cancel (D-27): the parent closes our stdin. Opt-in
	// only, so a "</dev/null" caller is never cancelled by accident (T-13-51).
	if *cancelOnStdinEOF && stdin != nil {
		go func() {
			_, _ = io.Copy(io.Discard, stdin)
			if ctx.Err() == nil {
				logger.Warn("stdin closed, cancelling pipeline")
			}
			cancel()
		}()
	}

	// The progress sink is a PURE NDJSON serializer: scanner.Run owns Seq/TS
	// (D-08); the sink marshals each already-populated Event to one stdout line
	// via the Emitter's atomic encode discipline (one JSON object per line, under
	// a mutex). stdout carries ONLY NDJSON; the payload goes to --payload-out.
	emitter := progress.NewEmitter(stdout)
	sink := func(ev progress.Event) {
		_ = emitter.Write(ev)
	}

	cfg := scanner.Config{
		CIDRs:          []string(cidrs),
		Timing:         *timing,
		Ports:          resolvedPorts,
		ProbeFragile:   *probeFragile,
		DetailedEvents: *events == "detailed",
	}

	pl, runErr := scanner.Run(ctx, cfg, sink)
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			logger.Error("pipeline cancelled", "err", runErr)
			// Write the partial payload marked "cancelled" (D-25) when Run
			// returned one. The exit code stays 130 regardless: a cancelled run
			// must never look upload-worthy to a caller (T-13-52).
			if pl.SchemaVersion != 0 {
				if err := writePayload(*payloadOut, pl); err != nil {
					logger.Error("partial payload write failed", "path", *payloadOut, "err", err)
				} else {
					logger.Info("partial payload written", "path", *payloadOut, "schema_version", pl.SchemaVersion)
				}
			}
			return 130
		}
		logger.Error("pipeline failed", "err", runErr)
		return 1
	}

	if err := writePayload(*payloadOut, pl); err != nil {
		logger.Error("payload write failed", "path", *payloadOut, "err", err)
		return 1
	}
	logger.Info("payload written", "path", *payloadOut, "schema_version", payload.SchemaVersion, "cidrs", len(cidrs))
	return 0
}
