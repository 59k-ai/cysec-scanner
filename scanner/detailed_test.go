// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/59k-ai/cysec-scanner/progress"
)

func collect(t *testing.T, ctx context.Context, cfg Config) ([]progress.Event, error) {
	t.Helper()
	var events []progress.Event
	_, err := Run(ctx, cfg, func(ev progress.Event) { events = append(events, ev) })
	return events, err
}

func assertContiguous(t *testing.T, events []progress.Event) {
	t.Helper()
	for i, ev := range events {
		if ev.Seq != i {
			t.Fatalf("event %d seq = %d, want contiguous from 0", i, ev.Seq)
		}
	}
}

// TestRunLegacyModeUnchanged proves legacy mode emits exactly the 5 legacy
// events, each marshalling to exactly the 8 legacy keys.
func TestRunLegacyModeUnchanged(t *testing.T) {
	events, err := collect(t, context.Background(), Config{CIDRs: testScope})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}
	want := []string{"agent", "assets", "errors", "kind", "phase", "seq", "ts", "warnings"}
	for i, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		if len(keys) != 8 {
			t.Errorf("event %d keys = %v, want %v", i, keys, want)
		}
		for _, k := range want {
			if _, ok := m[k]; !ok {
				t.Errorf("event %d missing key %q", i, k)
			}
		}
		if !strings.HasPrefix(string(b), `{"kind":`) {
			t.Errorf("event %d key order changed: %s", i, b)
		}
	}
	assertContiguous(t, events)
}

// TestRunDetailedEventsSequence proves the detailed stream frame: scan_start
// first, agent_done after each agent_start, scan_end{completed} last.
func TestRunDetailedEventsSequence(t *testing.T) {
	events, err := collect(t, context.Background(), Config{CIDRs: testScope, DetailedEvents: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertContiguous(t, events)

	first := events[0]
	if first.Kind != progress.ScanStart || first.Scan == nil {
		t.Fatalf("first event = %+v, want scan_start with scan info", first)
	}
	if !reflect.DeepEqual(first.Scan.Stages, []string{"discovery", "port", "fingerprint"}) {
		t.Errorf("stages = %v", first.Scan.Stages)
	}
	if !reflect.DeepEqual(first.Scan.Scope, testScope) {
		t.Errorf("scope = %v", first.Scan.Scope)
	}

	last := events[len(events)-1]
	if last.Kind != progress.ScanEnd || last.ScanEnd == nil || last.ScanEnd.Status != "completed" {
		t.Fatalf("last event = %+v, want scan_end completed", last)
	}

	var open *string
	starts, dones := 0, 0
	for _, ev := range events {
		switch ev.Kind {
		case progress.AgentStart:
			if open != nil {
				t.Fatalf("agent_start %q before agent_done of %q", *ev.Agent, *open)
			}
			open = ev.Agent
			starts++
		case progress.AgentDone:
			if open == nil || ev.Agent == nil || *ev.Agent != *open {
				t.Fatalf("agent_done %v does not match open agent %v", ev.Agent, open)
			}
			open = nil
			dones++
		}
	}
	if starts != 3 || dones != 3 {
		t.Errorf("agent_start=%d agent_done=%d, want 3/3", starts, dones)
	}
}

// TestRunDetailedLogsDroppedScopeEntries proves every malformed or IPv6 scope
// entry produces exactly one warn log naming the entry.
func TestRunDetailedLogsDroppedScopeEntries(t *testing.T) {
	cidrs := []string{"192.0.2.1/32", "10.0.0.0/33", "fe80::/64"}
	events, err := collect(t, context.Background(), Config{CIDRs: cidrs, DetailedEvents: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var warns []string
	for _, ev := range events {
		if ev.Kind == progress.Log && ev.Log != nil && ev.Log.Level == "warn" {
			warns = append(warns, ev.Log.Message)
		}
	}
	if len(warns) != 2 {
		t.Fatalf("warn logs = %v, want 2", warns)
	}
	for i, bad := range []string{"10.0.0.0/33", "fe80::/64"} {
		if !strings.Contains(warns[i], bad) {
			t.Errorf("warn %d = %q, want it to name %q", i, warns[i], bad)
		}
	}
}

// TestRunDetailedCancelledScanEnd proves a pre-cancelled run ends with
// scan_end{cancelled} and still returns context.Canceled.
func TestRunDetailedCancelledScanEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events, err := collect(t, ctx, Config{CIDRs: testScope, DetailedEvents: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	last := events[len(events)-1]
	if last.Kind != progress.ScanEnd || last.ScanEnd == nil || last.ScanEnd.Status != "cancelled" {
		t.Fatalf("last event = %+v, want scan_end cancelled", last)
	}
	assertContiguous(t, events)
}

// TestRunDetailedFailedScanEnd proves a stage error ends with an error log and
// scan_end{failed} carrying the error text.
func TestRunDetailedFailedScanEnd(t *testing.T) {
	boom := errors.New("boom\x1b[31m")
	cfg := Config{CIDRs: testScope, DetailedEvents: true, ExtraStages: []Stage{
		func(context.Context, *ScanContext) error { return boom },
	}}
	events, err := collect(t, context.Background(), cfg)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	last := events[len(events)-1]
	if last.ScanEnd == nil || last.ScanEnd.Status != "failed" || last.ScanEnd.Error == nil || *last.ScanEnd.Error != "boom[31m" {
		t.Fatalf("last event = %+v, want scan_end failed with sanitised error", last)
	}
	found := false
	for _, ev := range events {
		if ev.Kind == progress.Log && ev.Log != nil && ev.Log.Level == "error" {
			found = true
		}
	}
	if !found {
		t.Error("no error log emitted for the stage failure")
	}
}
