// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package pipeline is the staged scan runner skeleton (ENG-01): a fixed,
// deterministic sequence of stages — discovery -> port -> fingerprint —
// executed under one cancelable context.Context threaded from
// main, with feed-forward gating (a stage runs only if every prior stage
// succeeded, which the sequential-with-early-return loop provides for free).
//
// Phase 2 ships only the framework: the stage bodies are stubs (no-op). Real
// scanning logic lands from Phase 3 onward (D-04), filled in additively without
// changing this control flow.
package pipeline

import "context"

// StageName identifies one scan stage.
type StageName string

const (
	StageDiscovery   StageName = "discovery"
	StagePort        StageName = "port"
	StageFingerprint StageName = "fingerprint"
)

// Order is the fixed, deterministic stage order. The default pipeline runs its
// stages in exactly this sequence.
var Order = []StageName{StageDiscovery, StagePort, StageFingerprint}

// StageFunc is one stage body. Phase-2 bodies are no-ops.
type StageFunc func(ctx context.Context) error

// Stage pairs a stage name with its body.
type Stage struct {
	Name StageName
	Run  StageFunc
}

// Pipeline runs an ordered list of stages under one context.
type Pipeline struct {
	stages []Stage
}

// New returns the default Phase-2 pipeline: the four fixed stages, in Order,
// each with a stub (no-op) body.
func New() *Pipeline {
	return NewWithStages(defaultStages())
}

// NewWithStages returns a pipeline over the given ordered stages. Tests use this
// to inject instrumented bodies.
func NewWithStages(stages []Stage) *Pipeline {
	return &Pipeline{stages: stages}
}

func defaultStages() []Stage {
	stub := func(context.Context) error { return nil }
	out := make([]Stage, 0, len(Order))
	for _, name := range Order {
		out = append(out, Stage{Name: name, Run: stub})
	}
	return out
}

// Run executes the stages in order. Before each stage it checks ctx; if the
// context is already cancelled it returns the context error immediately and
// runs no further stage body (so a cancellation before the first stage runs
// zero bodies). onStage, when non-nil, is called with the stage name at the
// moment that stage begins (after the cancellation check, before the body).
func (p *Pipeline) Run(ctx context.Context, onStage func(StageName)) error {
	for _, st := range p.stages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if onStage != nil {
			onStage(st.Name)
		}
		if err := st.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}
