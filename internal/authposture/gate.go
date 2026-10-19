// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import "github.com/59k-ai/cysec-scanner/internal/payload"

// defaultAuthWorkers is the default size of the bounded per-host read pool. It
// sits inside the sanctioned [4,8] range (WINAD-04); the exact value within that
// range is discretionary.
const defaultAuthWorkers = 6

// Windows-indicative service ports: SMB over NetBIOS-less direct TCP (445), the
// DCOM/RPC endpoint mapper (135), and RDP (3389). An OS-unknown host with any of
// these open is a Windows candidate (D-03 port clause).
const (
	portSMB    = 445
	portEPMAP  = 135
	portRDP    = 3389
	osWindows  = "Windows"
	osUnknownV = "unknown"
)

// windowsGated reports whether an asset enters the authposture stage. It
// implements D-03 EXACTLY and admits a host in exactly two cases:
//
//	(a) a CONFIDENT Windows guess: OSGuess is non-nil and dereferences to
//	    "Windows"; OR
//	(b) the OS is UNKNOWN (OSGuess nil, or dereferences to "unknown") AND a
//	    Windows-indicative port (445/135/3389) is open.
//
// CRITICAL (D-03): the port clause is conditioned on OS-unknown. A host with a
// CONFIDENT non-Windows guess (e.g. "Linux" on a Samba/NAS box) that happens to
// have 445 open is REJECTED, so the read credential is never offered to a
// known-non-Windows host. A non-Windows SMB host that slips through as "unknown"
// simply returns AccessDenied on the authenticated read and is dropped —
// read-only, safe.
func windowsGated(ai payload.AssetItem) bool {
	if ai.OSGuess != nil && *ai.OSGuess == osWindows {
		return true
	}
	if !osUnknown(ai) {
		return false
	}
	for _, s := range ai.Services {
		if s.Port == portSMB || s.Port == portEPMAP || s.Port == portRDP {
			return true
		}
	}
	return false
}

// osUnknown reports whether the asset's OS guess is unknown: a nil OSGuess, or
// one that dereferences to the literal "unknown". Any other confident value
// (including a non-Windows one) is NOT unknown and keeps the port clause closed.
func osUnknown(ai payload.AssetItem) bool {
	return ai.OSGuess == nil || *ai.OSGuess == osUnknownV
}

// clampWorkers clamps a requested worker count into the inclusive [4,8] range
// (WINAD-04). A value below the floor is raised to 4 and one above the ceiling
// is lowered to 8; a value outside the range is clamped, never rejected. The
// bound is integer-only, so there is no rounding or precision loss.
func clampWorkers(n int) int {
	const lo, hi = 4, 8
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
