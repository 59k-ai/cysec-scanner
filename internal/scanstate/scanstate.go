// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package scanstate holds the in-progress v5 payload that scan stages
// contribute to as the pipeline runs.
//
// It is the accumulator seam (Phase-3 discretion decision): the discovery stage
// writes discovered assets here, later stages (port, fingerprint, authposture)
// enrich the same accumulator, and main.go snapshots it after the pipeline to
// marshal the wire payload. The pipeline control-flow package is left untouched
// — stage closures built in main.go capture a *ScanState — so the existing
// order/cancel/gating tests pass verbatim (ENG-01).
//
// The sweep is concurrent, so every mutation is guarded by a mutex (the race
// detector gate is the proof this holds).
package scanstate

import (
	"sync"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// ScanState is the shared, thread-safe accumulator for the in-progress payload.
type ScanState struct {
	mu sync.Mutex
	pl payload.Payload
}

// New returns a ScanState seeded with an empty-ish strict-valid v5 payload (the
// given payload_type and collector_version; every required slice already an
// empty literal).
func New(payloadType, collectorVersion string) *ScanState {
	return &ScanState{pl: payload.NewEmpty(payloadType, collectorVersion)}
}

// AddAsset appends one discovered asset to the accumulated payload. Safe for
// concurrent callers.
func (s *ScanState) AddAsset(a payload.AssetItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pl.Assets = append(s.pl.Assets, a)
}

// Payload returns a snapshot of the accumulated payload with its asset slice
// copied, so the caller can mutate/Normalize the result without racing ongoing
// writers or aliasing internal state.
func (s *ScanState) Payload() payload.Payload {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.pl
	snap.Assets = append([]payload.AssetItem(nil), s.pl.Assets...)
	return snap
}

// Assets returns a snapshot copy of the accumulated asset slice under lock, so a
// later scanning stage (port, fingerprint, authposture) can read the hosts the
// discovery stage recorded without racing concurrent writers or aliasing the
// internal slice. The copy is shallow: the AssetItem values are safe to inspect,
// but writing enrichment back MUST go through UpdateAsset so the mutation is
// applied under the same lock.
func (s *ScanState) Assets() []payload.AssetItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]payload.AssetItem(nil), s.pl.Assets...)
}

// UpdateAsset locates the accumulated asset whose ExternalID matches and applies
// fn to it in place under lock; it is a no-op when no asset matches. This is the
// merge seam a later stage uses to enrich a discovered asset (add services,
// merge a refined classification) without replacing the accumulator or touching
// the pipeline control-flow package. fn runs while the lock is held, so it must
// not call back into ScanState (which would deadlock).
func (s *ScanState) UpdateAsset(externalID string, fn func(*payload.AssetItem)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.pl.Assets {
		if s.pl.Assets[i].ExternalID == externalID {
			fn(&s.pl.Assets[i])
			return
		}
	}
}
