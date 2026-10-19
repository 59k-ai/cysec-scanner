// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
	"github.com/59k-ai/cysec-scanner/payload"
)

// Stage is a public pipeline stage (D-04): a unit of scan work that runs against
// the narrow ScanContext facade. Run executes the built-in default stages first,
// then every Config.ExtraStages in declared order (D-06).
type Stage func(ctx context.Context, sc *ScanContext) error

// ScanContext is the narrow public facade a Stage sees (D-04). It exposes ONLY
// the accumulator accessors a stage needs plus the immutable runtime
// Capabilities; the internal accumulator stays hidden behind it and owns the
// lock — the facade adds no locking of its own, it forwards.
type ScanContext struct {
	st *scanstate.ScanState
	// Capabilities is the immutable runtime capability snapshot detected once at
	// the start of Run (ENG-06), surfaced read-only. It is a value, not a pointer:
	// a stage cannot mutate the detected truth.
	Capabilities capabilities.Capabilities
}

// Assets returns a snapshot copy of the accumulated assets. The copy is shallow:
// the values are safe to inspect, but writing enrichment back MUST go through
// UpdateAsset so the mutation applies under the accumulator lock.
func (sc *ScanContext) Assets() []payload.AssetItem {
	return sc.st.Assets()
}

// UpdateAsset locates the accumulated asset whose ExternalID matches and applies
// fn to it in place under the accumulator lock; it is a no-op when no asset
// matches. fn runs while the lock is held, so it MUST NOT call back into
// ScanContext (which would deadlock).
func (sc *ScanContext) UpdateAsset(externalID string, fn func(*payload.AssetItem)) {
	sc.st.UpdateAsset(externalID, fn)
}
