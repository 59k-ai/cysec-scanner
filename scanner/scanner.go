// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package scanner is the public, importable entry point to the read-only scan
// engine. A consumer drives the whole pipeline in-process via Run with a typed
// Config, stage registration (DefaultStages / Config.ExtraStages), and context
// cancellation — with no proprietary knowledge (LIB-02/LIB-03).
//
// The surface is deliberately minimal (D-02): only Run, Config, Stage,
// DefaultStages, the ScanContext facade, and the ProgressSink alias are
// exported; the scanning stage bodies stay internal and run only via Run. The
// engine opens no inbound/listening socket — progress leaves only through the
// in-process ProgressSink callback (LIB-06).
package scanner

import (
	"context"
	"strconv"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/discovery"
	"github.com/59k-ai/cysec-scanner/internal/fingerprint"
	"github.com/59k-ai/cysec-scanner/internal/portscan"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
	"github.com/59k-ai/cysec-scanner/payload"
	"github.com/59k-ai/cysec-scanner/progress"
)

// ProgressSink is the public progress callback (D-07). It aliases
// progress.ProgressSink so the locked Run signature reads in-package AND the
// identifier scanner.ProgressSink resolves for external consumers.
type ProgressSink = progress.ProgressSink

// collectorVersion stamps the payload's collector_version field for this engine.
const collectorVersion = "cysec-scanner-engine/0.0.0"

// fullPayloadType is the payload_type for a complete assessment run ("full" is a
// valid PayloadType enum member).
const fullPayloadType = "full"

// Config carries the typed, proprietary-agnostic knobs for a scan run. It names,
// sees, and carries no auth field of any kind (D-05): a stage that needs its own
// secret source captures it in a closure and is appended via ExtraStages.
type Config struct {
	// CIDRs is the scan scope; empty means auto-detect the local subnet.
	CIDRs []string
	// Timing is the scan timing-tier name ("polite"/"normal"/"aggressive"); empty
	// or unrecognized resolves to the safe polite tier.
	Timing string
	// Ports is the explicit TCP port set to probe; empty uses the curated default.
	Ports []int
	// ProbeFragile enables intrusive probing of fragile devices otherwise skipped.
	ProbeFragile bool
	// ExtraStages run AFTER the three built-in default stages, in declared slice
	// order (D-06). The built-in defaults always run first.
	ExtraStages []Stage
}

// DefaultStages returns the three non-proprietary built-in stages (discovery,
// port, fingerprint) in order (LIB-03). The proprietary authposture stage is NOT
// in the public default order; a consumer authors it against ScanContext and
// appends it via Config.ExtraStages. The returned stages carry curated default
// options; Run builds its own default closures from Config and does not call
// this — DefaultStages is the public, inspectable statement of the default order.
func DefaultStages() []Stage {
	return []Stage{
		func(ctx context.Context, sc *ScanContext) error {
			return discovery.Run(ctx, sc.st, sc.Capabilities, nil)
		},
		func(ctx context.Context, sc *ScanContext) error {
			return portscan.Run(ctx, sc.st, sc.Capabilities, portscan.Options{
				Tier:  portscan.ResolveTier(""),
				Ports: portscan.DefaultPortSet,
			})
		},
		func(ctx context.Context, sc *ScanContext) error {
			return fingerprint.Run(ctx, sc.st, sc.Capabilities, fingerprint.Options{})
		},
	}
}

// namedStage pairs a stage body with the agent name used for its progress event.
type namedStage struct {
	name string
	run  func(context.Context) error
}

// Run drives the staged scan to completion and returns the accumulated,
// Normalize()d payload. It detects runtime capabilities once (ENG-06), assembles
// the three built-in default stages against the internal accumulator directly
// (D-02), appends Config.ExtraStages wrapped against the public ScanContext
// facade in declared order (D-06), then runs them under one cancelable loop:
// ctx is checked BEFORE each stage, so a ctx canceled before the first stage
// runs zero stage bodies, and a stage error short-circuits the rest
// (feed-forward). Run OWNS progress sequencing (D-08): each Event gets a
// contiguous monotonic Seq from 0 and a wall-clock TS before the sink (when
// non-nil) is invoked; the sink is a pure serializer. The signature is locked.
func Run(ctx context.Context, cfg Config, sink ProgressSink) (payload.Payload, error) {
	caps := capabilities.Detect()
	st := scanstate.New(fullPayloadType, collectorVersion)
	sc := &ScanContext{st: st, Capabilities: caps}

	ports := cfg.Ports
	if len(ports) == 0 {
		ports = portscan.DefaultPortSet
	}

	stages := []namedStage{
		{"discovery", func(ctx context.Context) error {
			return discovery.Run(ctx, st, caps, cfg.CIDRs)
		}},
		{"port", func(ctx context.Context) error {
			return portscan.Run(ctx, st, caps, portscan.Options{Tier: portscan.ResolveTier(cfg.Timing), Ports: ports})
		}},
		{"fingerprint", func(ctx context.Context) error {
			return fingerprint.Run(ctx, st, caps, fingerprint.Options{ProbeFragile: cfg.ProbeFragile})
		}},
	}
	for i := range cfg.ExtraStages {
		extra := cfg.ExtraStages[i]
		stages = append(stages, namedStage{
			name: "extra" + strconv.Itoa(i),
			run: func(ctx context.Context) error {
				return extra(ctx, sc)
			},
		})
	}

	var seq int
	emit := func(kind progress.Kind, phase string, agent *string) {
		if sink != nil {
			sink(progress.Event{
				Kind:  kind,
				Seq:   seq,
				TS:    float64(time.Now().UnixNano()) / 1e9,
				Phase: phase,
				Agent: agent,
			})
		}
		seq++
	}

	emit(progress.PhaseStart, "collect", nil)
	var runErr error
	for _, ns := range stages {
		if err := ctx.Err(); err != nil {
			runErr = err
			break
		}
		name := ns.name
		emit(progress.AgentStart, "collect", &name)
		if err := ns.run(ctx); err != nil {
			runErr = err
			break
		}
	}
	emit(progress.PhaseDone, "collect", nil)
	if runErr != nil {
		return payload.Payload{}, runErr
	}

	pl := st.Payload()
	pl.Normalize()
	return pl, nil
}
