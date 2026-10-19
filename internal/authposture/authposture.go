// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// Package authposture is the pipeline's authenticated Windows/AD posture stage.
// It runs AFTER fingerprint and reads, over authenticated but strictly READ-ONLY
// RPC/LDAP, the posture of the hosts the fingerprint stage identified as Windows
// (the is_windows gate, D-03). The reads land on the shared accumulator's v6
// payload slices (software_inventory, missing_kbs, configuration_checks,
// password_policies, identities) plus asset-level OS fields.
//
// The stage is bounded, read-only and never-raises (WINAD-04, ENG-06, D-06):
//   - Fan-out over gated hosts is capped by a bounded worker pool clamped to the
//     [4,8] range (clampWorkers); the host-cap semaphore alone satisfies the
//     concurrency bound — no per-packet rate limiter is needed (not a socket
//     sweep).
//   - Every degraded condition (no credential, no Windows hosts, an unreachable
//     host, an AccessDenied, an empty result) returns nil and records a per-check
//     evidence note; it is NEVER a stage error. A returned error would fail the
//     whole pipeline and drop an otherwise strict-valid payload.
//   - When no Windows credential is supplied the stage self-skips (D-06): the
//     in-scope Windows hosts still ship baseline-only with an explicit
//     "no credential supplied" evidence note.
//
// Reader seams (one per protocol file) each populate ONLY their own slice of the
// single hostFacts contract and NEVER call ScanState. authposture.go is the ONE
// merge point: after the readers return it merges each host's combined facts
// through UpdateAsset (asset-level OS fields + evidence notes, under the lock)
// and the scanstate Add* accessors (the top-level slices, outside the lock).
// Because the merge lives here, the Wave-2 expansion plans only populate their
// reader's slice of hostFacts and never touch this file or scanstate (file
// disjoint). The pipeline control-flow package stays untouched (a closure built
// in main.go captures the accumulator).
package authposture

import (
	"context"
	"sync"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
)

// DefaultWorkers is the exported default bounded-pool size for callers (main.go
// wiring). It equals the package default and lies inside the [4,8] range.
const DefaultWorkers = defaultAuthWorkers

// Evidence-map keys and note values this stage stamps on a gated asset's
// classification evidence. They are posture provenance only and never feed a
// compliance verdict (the verdict stays deterministic and cloud-side).
const (
	evidenceKeyNoCredential = "authposture_no_credential"
	evidenceKeyOSVersion    = "authposture_os_version"
	noteNoCredential        = "no credential supplied"
)

// Options carries the env-sourced read-only domain scan credential (D-05) and the
// requested bounded-pool worker count. The credential is passed to readers as a
// value and is NEVER logged or written into any payload field.
type Options struct {
	DomainUser string
	Password   string
	Workers    int
}

// hasCredential reports whether a usable Windows scan credential was supplied.
// Both the DOMAIN-user and the password must be present; a missing either half
// triggers the D-06 self-skip.
func (o Options) hasCredential() bool {
	return o.DomainUser != "" && o.Password != ""
}

// scanCredential is the single read-only domain scan account (D-05), handed to
// each reader by value. It never appears in a log line or a payload field.
type scanCredential struct {
	domainUser string
	password   string
}

// hostFacts is the ONE contract every reader populates and the ONE thing
// authposture merges. Each reader fills ONLY its own fields and NEVER calls
// ScanState; authposture.go performs the single merge. It carries the
// asset-level OS fields plus the five top-level payload slices, and a per-check
// error/evidence note map.
type hostFacts struct {
	operatingSystem  string
	osVersion        string
	software         []payload.SoftwareInventoryItem
	missingKbs       []payload.MissingKbItem
	configChecks     []payload.ConfigurationCheckItem
	passwordPolicies []payload.PasswordPolicyItem
	identities       []payload.IdentityItem
	notes            map[string]string
}

// newHostFacts returns an empty hostFacts with an allocated note map.
func newHostFacts() hostFacts {
	return hostFacts{notes: map[string]string{}}
}

// note records one per-check error/evidence note (a reader surfaces a degraded
// condition here rather than returning an error).
func (hf *hostFacts) note(key, val string) {
	if hf.notes == nil {
		hf.notes = map[string]string{}
	}
	hf.notes[key] = val
}

// absorb folds another reader's facts into this one: non-empty OS fields win,
// every top-level slice is concatenated, and all notes are copied. It is how one
// host's three reader results combine into a single merge.
func (hf *hostFacts) absorb(other hostFacts) {
	if other.operatingSystem != "" {
		hf.operatingSystem = other.operatingSystem
	}
	if other.osVersion != "" {
		hf.osVersion = other.osVersion
	}
	hf.software = append(hf.software, other.software...)
	hf.missingKbs = append(hf.missingKbs, other.missingKbs...)
	hf.configChecks = append(hf.configChecks, other.configChecks...)
	hf.passwordPolicies = append(hf.passwordPolicies, other.passwordPolicies...)
	hf.identities = append(hf.identities, other.identities...)
	for k, v := range other.notes {
		hf.note(k, v)
	}
}

// Run executes the authposture stage over the accumulator's gated Windows hosts.
// It mirrors the sibling stage signature; caps is reserved for parity and
// assigned to the blank identifier (an authenticated network reader needs no
// privileged-socket capability). It returns nil on every degraded condition so a
// fully-degraded run still yields a complete, strict-valid payload.
func Run(ctx context.Context, st *scanstate.ScanState, caps capabilities.Capabilities, opts Options) error {
	_ = caps // capabilities reserved for parity with the sibling stage signature

	gated := gatedHosts(st.Assets())
	if len(gated) == 0 {
		return nil
	}

	// D-06 no-credential skip: stamp each gated host baseline-only with an
	// explicit "no credential supplied" evidence note and return (stage skipped).
	// The run still ships a complete, strict-valid payload.
	if !opts.hasCredential() {
		for _, a := range gated {
			stampNoCredential(st, a.ExternalID)
		}
		return nil
	}

	cred := scanCredential{domainUser: opts.DomainUser, password: opts.Password}

	// Bounded host fan-out (WINAD-04): the semaphore caps in-flight reads to the
	// clamped worker count; facts are collected under a mutex and merged only
	// after every reader returns.
	sem := make(chan struct{}, clampWorkers(opts.Workers))
	var wg sync.WaitGroup
	var mu sync.Mutex
	factsByAsset := make(map[string]hostFacts, len(gated))

	for _, a := range gated {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(a payload.AssetItem) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			// The three reader seams run OUTSIDE any accumulator lock and each
			// returns facts only. authposture.go is the single merge point below.
			combined := newHostFacts()
			combined.absorb(readWMI(ctx, a, cred))
			combined.absorb(readWinreg(ctx, a, cred))
			combined.absorb(readAD(ctx, a, cred))
			mu.Lock()
			factsByAsset[a.ExternalID] = combined
			mu.Unlock()
		}(a)
	}
	wg.Wait()

	for id, hf := range factsByAsset {
		mergeFacts(st, id, hf)
	}
	return nil
}

// gatedHosts filters a snapshot of assets to the Windows-gated set (D-03).
func gatedHosts(assets []payload.AssetItem) []payload.AssetItem {
	var gated []payload.AssetItem
	for _, a := range assets {
		if windowsGated(a) {
			gated = append(gated, a)
		}
	}
	return gated
}

// mergeFacts is the SINGLE merge point. It appends every top-level slice through
// the scanstate Add* accessors (outside the asset lock) and then merges the
// asset-level OS fields and evidence notes in place under the accumulator lock.
// The closure passed to UpdateAsset makes NO ScanState calls (it would deadlock).
func mergeFacts(st *scanstate.ScanState, externalID string, hf hostFacts) {
	for _, s := range hf.software {
		st.AddSoftwareInventory(s)
	}
	for _, k := range hf.missingKbs {
		st.AddMissingKb(k)
	}
	for _, c := range hf.configChecks {
		st.AddConfigurationCheck(c)
	}
	for _, p := range hf.passwordPolicies {
		st.AddPasswordPolicy(p)
	}
	for _, id := range hf.identities {
		st.AddIdentity(id)
	}
	st.UpdateAsset(externalID, func(ai *payload.AssetItem) {
		if hf.operatingSystem != "" {
			ai.OperatingSystem = hf.operatingSystem
		}
		ensureEvidence(ai)
		if hf.osVersion != "" {
			ai.Classification.Evidence[evidenceKeyOSVersion] = hf.osVersion
		}
		for k, v := range hf.notes {
			ai.Classification.Evidence[k] = v
		}
	})
}

// stampNoCredential records the D-06 "no credential supplied" evidence note on a
// gated host that was skipped because no scan credential was provided.
func stampNoCredential(st *scanstate.ScanState, externalID string) {
	st.UpdateAsset(externalID, func(ai *payload.AssetItem) {
		ensureEvidence(ai)
		ai.Classification.Evidence[evidenceKeyNoCredential] = noteNoCredential
	})
}

// ensureEvidence makes an asset's classification evidence map writable, nil-safe.
// A gated host that reached this stage has already been classified by the port
// stage, but if the verdict is somehow absent a neutral "unknown" classification
// is allocated so the evidence note lands on a strict-valid structure rather than
// fabricating a confident asset type.
func ensureEvidence(ai *payload.AssetItem) {
	if ai.Classification == nil {
		ai.Classification = &payload.ClassificationEvidence{AssetType: "unknown"}
	}
	if ai.Classification.Evidence == nil {
		ai.Classification.Evidence = map[string]string{}
	}
}
