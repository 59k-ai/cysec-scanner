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
	// serviceBanners is an OFF-WIRE side-channel keyed by asset external_id,
	// holding the text banners the port stage captured per open port. The
	// fingerprint stage reads it to match an already-captured banner without
	// re-dialing. It is internal state only and is NEVER serialized into the
	// payload (raw banners stay off the wire — size + privacy).
	serviceBanners map[string]map[int]string
}

// New returns a ScanState seeded with an empty-ish strict-valid payload (the
// given payload_type and collector_version; every required slice already an
// empty literal).
func New(payloadType, collectorVersion string) *ScanState {
	return &ScanState{
		pl:             payload.NewEmpty(payloadType, collectorVersion),
		serviceBanners: map[string]map[int]string{},
	}
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

// SetServiceBanners records, under lock, the text banners the port stage captured
// for one asset (keyed by port). The map is copied so the caller cannot mutate
// the stored side-channel after the call. This is OFF-WIRE state the fingerprint
// stage reads; it is never serialized into the payload.
func (s *ScanState) SetServiceBanners(externalID string, banners map[int]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[int]string, len(banners))
	for k, v := range banners {
		cp[k] = v
	}
	s.serviceBanners[externalID] = cp
}

// ServiceBanners returns a copy of the text banners recorded for one asset, or an
// empty map when none were captured. The copy prevents the caller from aliasing
// internal state.
func (s *ScanState) ServiceBanners(externalID string) map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.serviceBanners[externalID]
	out := make(map[int]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// SetRecogDBVersion records, under lock, the pinned service-fingerprint database
// version for this run into the payload's scan_metadata block (v6, FPRINT-04),
// allocating the block on first write. A later stage sets OSSignatureDBVersion
// through the same accessor pattern.
func (s *ScanState) SetRecogDBVersion(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pl.ScanMetadata == nil {
		s.pl.ScanMetadata = &payload.ScanMetadata{}
	}
	v := version
	s.pl.ScanMetadata.RecogDBVersion = &v
}

// SetOSSignatureDBVersion records, under lock, the pinned self-authored OS
// signature database version for this run into the payload's scan_metadata block
// (v6, FPRINT-04), allocating the block on first write. It mirrors
// SetRecogDBVersion exactly so both fingerprint-database provenance values are
// recorded through the same accessor pattern.
func (s *ScanState) SetOSSignatureDBVersion(version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pl.ScanMetadata == nil {
		s.pl.ScanMetadata = &payload.ScanMetadata{}
	}
	v := version
	s.pl.ScanMetadata.OSSignatureDBVersion = &v
}
