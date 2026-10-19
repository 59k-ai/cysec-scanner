// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// readWinreg is the remote-registry-over-SMB reader seam. It is a no-op stub in
// this plan and is filled by a later plan (06-03) with the SMB-signing / Lsa
// registry reads plus the live SMB2 negotiate probe, all strictly read-only. It
// returns an empty hostFacts and never raises, so the stage orchestration and the
// single merge in authposture.go are wired once and the Wave-2 plan edits only
// this file. Each reader populates ONLY its own slice of hostFacts and NEVER
// calls ScanState.
func readWinreg(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts {
	_ = ctx
	_ = ai
	_ = cred
	return newHostFacts()
}
