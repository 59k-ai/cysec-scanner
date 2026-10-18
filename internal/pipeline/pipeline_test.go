// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"testing"
)

// TestContextCancel proves ENG-01 cancellation: a context cancelled before Run
// halts the pipeline with a context cancellation error and runs no stage body.
func TestContextCancel(t *testing.T) {
	t.Parallel()

	var ran int
	stages := make([]Stage, 0, len(Order))
	for _, name := range Order {
		stages = append(stages, Stage{Name: name, Run: func(context.Context) error {
			ran++
			return nil
		}})
	}
	p := NewWithStages(stages)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	var observed []StageName
	err := p.Run(ctx, func(s StageName) { observed = append(observed, s) })

	if err == nil {
		t.Fatal("Run with a cancelled context returned nil, want a cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if ran != 0 {
		t.Errorf("ran %d stage bodies past the cancellation point, want 0", ran)
	}
	if len(observed) != 0 {
		t.Errorf("observed %v stage starts, want none after cancellation", observed)
	}
}

// TestStageOrder proves the stub stages execute in the fixed deterministic order
// discovery -> port -> fingerprint -> authposture when the context is live.
func TestStageOrder(t *testing.T) {
	t.Parallel()

	var observed []StageName
	if err := New().Run(context.Background(), func(s StageName) {
		observed = append(observed, s)
	}); err != nil {
		t.Fatalf("Run with a live context returned %v, want nil", err)
	}

	want := []StageName{StageDiscovery, StagePort, StageFingerprint, StageAuthPosture}
	if len(observed) != len(want) {
		t.Fatalf("observed %v stages, want %v", observed, want)
	}
	for i := range want {
		if observed[i] != want[i] {
			t.Errorf("stage %d = %q, want %q", i, observed[i], want[i])
		}
	}
}

// TestFeedForwardGating proves a stage failure stops the pipeline: no later
// stage runs once an earlier one returns an error.
func TestFeedForwardGating(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	var ran []StageName
	stages := []Stage{
		{Name: StageDiscovery, Run: func(context.Context) error { ran = append(ran, StageDiscovery); return nil }},
		{Name: StagePort, Run: func(context.Context) error { ran = append(ran, StagePort); return sentinel }},
		{Name: StageFingerprint, Run: func(context.Context) error { ran = append(ran, StageFingerprint); return nil }},
	}

	err := NewWithStages(stages).Run(context.Background(), nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run error = %v, want sentinel", err)
	}
	if len(ran) != 2 || ran[0] != StageDiscovery || ran[1] != StagePort {
		t.Errorf("ran %v, want discovery then port only (fingerprint must be gated off)", ran)
	}
}
