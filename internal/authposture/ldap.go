// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// readAD is the signed-LDAP / Active Directory reader seam. It is a no-op stub in
// this plan and is filled by a later plan (06-04) with the signed bind, the
// default-domain password policy read, and the identity enumeration, all strictly
// read-only. It returns an empty hostFacts and never raises, so the stage
// orchestration and the single merge in authposture.go are wired once and the
// Wave-2 plan edits only this file (and brings its own LDAP dependency). Each
// reader populates ONLY its own slice of hostFacts and NEVER calls ScanState.
func readAD(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts {
	_ = ctx
	_ = ai
	_ = cred
	return newHostFacts()
}
