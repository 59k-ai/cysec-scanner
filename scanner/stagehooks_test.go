// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/progress"
)

// TestDetailedRunEmitsStageProgress proves the built-in discovery stage feeds
// stage_progress through the scanner emitter in detailed mode, and that legacy
// mode emits no stage_progress or host events.
func TestDetailedRunEmitsStageProgress(t *testing.T) {
	caps := capabilities.Detect()
	if !caps.UnprivilegedICMP && !caps.SystemPing {
		// No liveness probe on this host: the sweep short-circuits before any
		// probe runs, so there is no progress to observe (ENG-06 degrade path).
		t.Skip("no ICMP path available; sweep yields no probes")
	}
	events, err := collect(t, context.Background(), Config{CIDRs: []string{"192.0.2.1/32"}, DetailedEvents: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	found := false
	for _, ev := range events {
		if ev.Kind == progress.StageProgress && ev.Agent != nil && *ev.Agent == "discovery" &&
			ev.Progress != nil && ev.Progress.Total == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no discovery stage_progress with total 1 in %d events", len(events))
	}

	legacy, err := collect(t, context.Background(), Config{CIDRs: []string{"192.0.2.1/32"}})
	if err != nil {
		t.Fatalf("Run (legacy): %v", err)
	}
	for _, ev := range legacy {
		if ev.Kind == progress.StageProgress || ev.Kind == progress.Host {
			t.Fatalf("legacy mode emitted %s", ev.Kind)
		}
	}
}
