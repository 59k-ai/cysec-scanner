// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package fingerprint is the pipeline's service/OS fingerprinting stage. It runs
// AFTER the port stage and enriches the same accumulator the earlier stages
// populated: for each asset it reads the banners the port stage already captured
// (from the off-wire side-channel — no second dial), matches them against the
// vendored service-fingerprint database, and promotes a higher-fidelity match
// into the asset's structured service identity (product / version / CPE) with a
// source label and numeric confidence.
//
// Precedence (D-11, higher-fidelity-wins): a match at or above the prefer-unknown
// confidence cut OVERWRITES the lower-fidelity light-parse value from the port
// stage and re-labels the source; a below-cut or no-match result LEAVES the
// existing value and its source label intact — a miss never nulls a good value.
//
// The stage is read-only, bounded and never-raises (D-14): a dark, hostile,
// empty or unparseable banner yields no enrichment and no error, and a database
// that fails to load degrades the stage to a no-op rather than failing the run.
// It writes through the accumulator's UpdateAsset seam only, so the pipeline
// control-flow package stays untouched (D-13).
package fingerprint

import (
	"context"
	"regexp"
	"strings"

	scannerdata "github.com/cysec-watch/cysec-scanner"
	"github.com/cysec-watch/cysec-scanner/internal/capabilities"
	"github.com/cysec-watch/cysec-scanner/internal/fingerprint/recog"
	"github.com/cysec-watch/cysec-scanner/internal/governance"
	"github.com/cysec-watch/cysec-scanner/internal/payload"
	"github.com/cysec-watch/cysec-scanner/internal/scanstate"
)

// sourceRecogV1 is the provenance label this stage stamps on a service identity
// promoted from a service-fingerprint-database match.
const sourceRecogV1 = "recog-v1"

// confidenceCut is the prefer-unknown confidence cut (inclusive): a match with
// confidence >= cut is promoted as authoritative; below the cut the structured
// identity is suppressed rather than shown as a weak claim (FPRINT-03, D-07).
const confidenceCut = 0.5

// sshDBPath is the embedded, governed service-fingerprint database this stage
// matches SSH banners against.
const sshDBPath = "data/recog/ssh_banners.xml"

// Options carries the resolved per-scan fingerprint settings. ProbeFragile is the
// operator override that enables intrusive probing of fragile devices; it is
// unused by the passive baseline and established here for a later privileged
// stage to consult the same gate.
type Options struct {
	ProbeFragile bool
}

// sshIdentRe captures the "software and comment" portion of an SSH identification
// string (everything after the "SSH-<proto>-" prefix), which is what the SSH
// fingerprint database matches against.
var sshIdentRe = regexp.MustCompile(`^SSH-\d+\.\d+-(.*)$`)

// Run executes the fingerprint stage over the accumulator's assets. It returns
// nil on any degraded condition (no assets, database load failure, cancellation)
// so a fully-degraded run still yields a complete, strict-valid payload.
func Run(ctx context.Context, st *scanstate.ScanState, caps capabilities.Capabilities, opts Options) error {
	_ = caps // capabilities reserved for later privileged probe paths
	_ = opts // ProbeFragile reserved for the later intrusive-probe gate

	db, err := recog.Load(scannerdata.DataFS, sshDBPath)
	if err != nil {
		// Never-raises: a database that cannot load degrades the stage to a no-op.
		return nil
	}

	// Record the pinned database version once per run (FPRINT-04), read from the
	// governed data manifest — never a hand-maintained duplicate constant.
	if v := recogDBVersion(); v != "" {
		st.SetRecogDBVersion(v)
	}

	for _, a := range st.Assets() {
		if ctx.Err() != nil {
			return nil
		}
		banners := st.ServiceBanners(a.ExternalID)
		if len(banners) == 0 {
			continue
		}
		st.UpdateAsset(a.ExternalID, func(ai *payload.AssetItem) {
			for i := range ai.Services {
				banner, ok := banners[ai.Services[i].Port]
				if !ok {
					continue
				}
				comment := sshComment(banner)
				if comment == "" {
					continue
				}
				id, matched := db.Match(comment)
				if !matched {
					continue
				}
				applyServiceIdentity(&ai.Services[i], id, confidenceCut)
			}
		})
	}
	return nil
}

// applyServiceIdentity promotes a service-fingerprint match into a service item
// when the match is authoritative: it must carry a product and meet the
// confidence cut (inclusive). On promotion it OVERWRITES the product / version /
// CPE triple from the match and stamps the source + numeric confidence. A match
// below the cut, or one carrying no product, leaves the existing value and its
// source untouched (D-11 — a miss never nulls a good value). It reports whether
// a promotion occurred.
func applyServiceIdentity(s *payload.ServiceItem, id recog.Identity, cut float64) bool {
	if s == nil || id.Product == "" || id.Confidence < cut {
		return false
	}
	product := id.Product
	s.Product = &product
	s.ServiceVersion = optional(id.ServiceVersion)
	s.CPE = optional(id.CPE)
	source := sourceRecogV1
	confidence := id.Confidence
	s.ServiceIdentitySource = &source
	s.ServiceIdentityConfidence = &confidence
	return true
}

// optional returns a pointer to s, or nil when s is empty — so an absent value
// marshals to JSON null rather than an empty string.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

// sshComment returns the software-and-comment portion of an SSH identification
// string, or "" for a banner that is not an SSH identification string.
func sshComment(banner string) string {
	m := sshIdentRe.FindStringSubmatch(banner)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// recogDBVersion returns the pinned upstream snapshot of the vendored service
// fingerprint database from the governed data manifest (FPRINT-04), or "" when
// the manifest or entry is unavailable. The manifest is the single provenance
// record, so the recorded version is deterministic for a given embedded build.
func recogDBVersion() string {
	entries, err := governance.LoadAllowlist(scannerdata.DataFS)
	if err != nil {
		return ""
	}
	entry, ok := entries[sshDBPath]
	if !ok {
		return ""
	}
	return entry.UpstreamSnapshot
}
