// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	winreg "github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// winreg.go is the remote-registry-over-SMB reader (the 06-01 readWinreg seam).
// It reads the six SMB-signing / Lsa DWORD values HKLM over a sealed SMB named
// pipe (ncacn_np:[winreg], which go-msrpc accepts only with seal or insecure —
// seal is used) and maps them onto configuration_checks, PRESERVING the tri-state:
// a present value, a present 0, and an absent value (ERROR_FILE_NOT_FOUND, 0x2)
// are three DISTINCT outcomes and an absent value is NEVER coerced to 0
// (spike-settled, WINAD-02). The live SMB2 negotiate probe + combiner live in
// smb2.go and are folded into this same readWinreg (see Task 2). All verbs are
// query-only; the reader is read-only and never-raises (a per-value failure lands
// a per-check note, never a stage error). It populates ONLY hostFacts and NEVER
// calls ScanState — authposture.go is the single merge point.

// errorFileNotFound is the Win32 status (ERROR_FILE_NOT_FOUND, 0x2) that MS-RRP
// returns when a value or subkey is absent. It is the authoritative "absent"
// signal and is the hinge of the tri-state: absent is NOT a present 0.
const errorFileNotFound uint32 = 0x2

// winregCallTimeout bounds the sealed named-pipe dial + each RPC so a dead or
// filtered host fails fast rather than hanging the bounded host pool.
const winregCallTimeout = 20 * time.Second

// Note keys this reader stamps on a host's classification evidence. They are
// posture provenance only and never feed a compliance verdict (cloud-side).
const (
	noteKeyWinreg = "authposture_winreg"
	noteKeySMB2   = "authposture_smb2"
)

// observedAbsent / observedError are the DISTINCT ObservedValue markers for the
// non-present tri-state outcomes. A present DWORD is rendered as its decimal
// (so a present 0 observes "0"), an absent value observes "absent" (never "0"),
// and a per-value read error observes "error". The three never collide.
const (
	observedAbsent = "absent"
	observedError  = "error"
)

// checkCodeServerRequired is the LanmanServer requiresecuritysignature row's
// check code; readWinreg carries that value's result forward into the combined
// effective-signing row (smb2.go).
const checkCodeServerRequired = "smb_signing:server_required"

// winregCredOnce-free: the single read-only scan account is registered once per
// process by registerWMICredential (wmi.go) over the shared go-msrpc gssapi store
// (same D-05 account, same NTLM mechanism); winreg reuses it.

// regOutcome is the tri-state class of one registry DWORD read.
type regOutcome int

const (
	regPresent regOutcome = iota // a DWORD was read (value valid, may be 0)
	regAbsent                    // ERROR_FILE_NOT_FOUND (0x2): value absent (OS default) — NOT a present 0
	regError                     // any other open/query failure (surfaced per-check, never-raises)
)

// regResult is one registry DWORD read's tri-state outcome. value is meaningful
// only when outcome == regPresent; err carries the per-check error for regError.
type regResult struct {
	outcome regOutcome
	value   uint32
	err     error
}

// winregValue is one entry of the authoritative SMB-signing / Lsa value set
// (windows-rpc.md). subkey+value name the HKLM read; checkCode/title name the
// configuration_checks row.
type winregValue struct {
	subkey    string
	value     string
	checkCode string
	title     string
}

// winregValues is the six SMB-signing / Lsa DWORD values read over the sealed
// named pipe (parity-locked to the spike, WINAD-05): LanmanServer
// requiresecuritysignature + enablesecuritysignature, LanmanWorkstation
// RequireSecuritySignature, and Lsa LmCompatibilityLevel, RunAsPPL,
// RestrictAnonymous.
var winregValues = []winregValue{
	{`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "requiresecuritysignature", checkCodeServerRequired, "SMB server signing required (LanmanServer\\requiresecuritysignature)"},
	{`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "enablesecuritysignature", "smb_signing:server_enabled", "SMB server signing enabled (LanmanServer\\enablesecuritysignature)"},
	{`SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`, "RequireSecuritySignature", "smb_signing:client_required", "SMB client signing required (LanmanWorkstation\\RequireSecuritySignature)"},
	{`SYSTEM\CurrentControlSet\Control\Lsa`, "LmCompatibilityLevel", "lsa:lm_compatibility_level", "LAN Manager authentication level (Lsa\\LmCompatibilityLevel)"},
	{`SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL", "lsa:run_as_ppl", "LSASS runs as a protected process (Lsa\\RunAsPPL)"},
	{`SYSTEM\CurrentControlSet\Control\Lsa`, "RestrictAnonymous", "lsa:restrict_anonymous", "Restrict anonymous access (Lsa\\RestrictAnonymous)"},
}

// winregSession reads DWORD values from one host over an established sealed
// winreg session. liveWinregSession is the real implementation; tests inject a
// fake returning canned tri-state results so the mapping is exercised on Linux
// CI without a real Windows target.
type winregSession interface {
	queryDword(ctx context.Context, subkey, value string) regResult
	close()
}

// openWinregSession dials the host and opens HKLM over the sealed named pipe. It
// is a package-var seam swapped in tests (a fake session, or a dial error) so the
// never-raises mapping path is testable off-Windows.
var openWinregSession = openLiveWinregSession

// winregValueNoteKey derives the per-value evidence-note key for a degraded read
// of one registry value, so one value's failure never masks another's.
func winregValueNoteKey(value string) string { return noteKeyWinreg + "_" + value }

// observedFromResult renders a tri-state registry result into a DISTINCT
// ObservedValue string: a present DWORD -> its decimal (present 0 -> "0"), an
// absent value -> "absent" (NEVER "0"), a read error -> "error".
func observedFromResult(r regResult) string {
	switch r.outcome {
	case regPresent:
		return strconv.FormatUint(uint64(r.value), 10)
	case regAbsent:
		return observedAbsent
	default:
		return observedError
	}
}

// regConfigCheck builds one configuration_checks evidence row for a registry
// value. Status is the neutral "collected" (evidence, not a verdict — the NIS2
// mapping is applied cloud-side) and ExpectedValue is left empty (the scanner
// asserts no expectation). The tri-state survives onto the wire via ObservedValue.
func regConfigCheck(externalID string, w winregValue, r regResult) payload.ConfigurationCheckItem {
	return payload.ConfigurationCheckItem{
		AssetExternalID: externalID,
		CheckCode:       w.checkCode,
		Title:           w.title,
		Status:          checkStatusCollected,
		Severity:        severityInfo,
		ObservedValue:   observedFromResult(r),
	}
}

// readWinreg reads the six SMB-signing / Lsa values over a sealed SMB named pipe,
// tri-stating absent-vs-present-0 onto configuration_checks, and NEVER raises: a
// dial/session failure or any per-value failure lands a per-check note and the
// stage still ships a complete payload. The live SMB2 negotiate probe + combiner
// (smb2.go) are folded in here by Task 2.
func readWinreg(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts {
	hf := newHostFacts()
	host := targetHost(ai)
	if host == "" {
		hf.note(noteKeyWinreg, "no_address")
		return hf
	}
	// The single read-only scan account (D-05) is registered once per process over
	// the shared go-msrpc gssapi store; winreg reuses the WMI registration.
	registerWMICredential(cred)

	// Attempt the sealed registry read. A whole-session failure (dial/seal/HKLM
	// open) is a per-check note, not a stage error, and adds NO registry rows — but
	// the independent SMB2 probe below still runs (never-raises). The server-signing
	// value's result is carried forward for the combiner.
	var serverRequired regResult
	var haveServerRequired bool
	if sess, err := openWinregSession(ctx, host); err != nil {
		hf.note(noteKeyWinreg, "session: "+err.Error())
	} else {
		defer sess.close()
		// Read each value independently: a per-value failure lands a per-check note
		// and observes "error" while the other values still map. The tri-state
		// (present / present-0 / absent) survives onto each row's ObservedValue;
		// absent is NEVER coerced to 0.
		for _, w := range winregValues {
			r := sess.queryDword(ctx, w.subkey, w.value)
			if r.outcome == regError && r.err != nil {
				hf.note(winregValueNoteKey(w.value), r.err.Error())
			}
			hf.configChecks = append(hf.configChecks, regConfigCheck(ai.ExternalID, w, r))
			if w.checkCode == checkCodeServerRequired {
				serverRequired, haveServerRequired = r, true
			}
		}
	}

	// Combine the registry read with a LIVE SMB2 negotiate probe (WINAD-02): a
	// modern client whose server-signing value is absent-by-default yet effectively
	// requires signing must not be false-negatived. A probe failure degrades to the
	// registry-only rows plus a per-check note (never-raises).
	probe := probeSMB2(ctx, host)
	if !probe.ok {
		hf.note(noteKeySMB2, "negotiate_probe_unavailable")
	}
	// Emit the combined effective-signing row only when there is SOME signal
	// (a registry server-signing result or a successful probe); with neither, the
	// host simply carries the per-check notes (keeps a fully-degraded read from
	// fabricating an "unknown" verdict row).
	if haveServerRequired || probe.ok {
		hf.configChecks = append(hf.configChecks,
			effectiveSigningCheck(ai.ExternalID, serverRequired, haveServerRequired, probe))
	}
	return hf
}

// openLiveWinregSession dials the host's SMB named-pipe winreg endpoint
// (ncacn_np:[winreg]) with seal (go-msrpc accepts only seal or insecure on the
// SMB named pipe — seal is mandatory, spike-settled / T-6-03) and opens HKLM for
// query-only access. Every verb on the returned session is query-only; there is
// no write/create/delete verb anywhere in this file (WINAD-04 read-only).
func openLiveWinregSession(ctx context.Context, host string) (winregSession, error) {
	// A no-op logger: go-msrpc debug output must never reach stderr (it could echo
	// authentication material), so it is discarded outright.
	log := zerolog.Nop()

	sctx := gssapi.NewSecurityContext(ctx)
	cc, err := dcerpc.Dial(sctx, host, dcerpc.WithEndpoint("ncacn_np:[winreg]"),
		dcerpc.WithLogger(log), dcerpc.WithTimeout(winregCallTimeout))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	cli, err := winreg.NewWinregClient(sctx, cc, dcerpc.WithSeal())
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("winreg_client: %w", err)
	}
	hklm, err := cli.OpenLocalMachine(sctx, &winreg.OpenLocalMachineRequest{
		DesiredAccess: winreg.KeyQueryValue,
	})
	if err != nil {
		cc.Close(sctx)
		return nil, fmt.Errorf("open_hklm: %w", err)
	}
	return &liveWinregSession{ctx: sctx, cc: cc, cli: cli, hklm: hklm.Key}, nil
}

// liveWinregSession is the real sealed winreg session over one SMB named-pipe
// connection. queryDword opens the subkey and queries the value, mapping the
// MS-RRP ERROR_FILE_NOT_FOUND (0x2) return code to the DISTINCT regAbsent outcome
// so an absent value is never coerced to a present 0.
type liveWinregSession struct {
	ctx  context.Context
	cc   dcerpc.Conn
	cli  winreg.WinregClient
	hklm *winreg.Key
}

// queryDword opens one subkey and queries one value name (NUL-terminated), both
// query-only. go-msrpc returns the response struct alongside a non-nil error on a
// non-zero MS-RRP return code, so an absent value/subkey is detected
// authoritatively via Return == ERROR_FILE_NOT_FOUND (0x2) and mapped to
// regAbsent — distinct from a present DWORD 0. Any other failure is regError.
func (s *liveWinregSession) queryDword(_ context.Context, subkey, value string) regResult {
	open, err := s.cli.BaseRegOpenKey(s.ctx, &winreg.BaseRegOpenKeyRequest{
		Key:           s.hklm,
		SubKey:        &winreg.UnicodeString{Buffer: subkey + "\u0000"},
		DesiredAccess: winreg.KeyQueryValue,
	})
	if err != nil {
		if open != nil && open.Return == errorFileNotFound {
			return regResult{outcome: regAbsent}
		}
		return regResult{outcome: regError, err: fmt.Errorf("open_key: %w", err)}
	}
	q, err := s.cli.BaseRegQueryValue(s.ctx, &winreg.BaseRegQueryValueRequest{
		Key:        open.ResultKey,
		ValueName:  &winreg.UnicodeString{Buffer: value + "\u0000"},
		Data:       make([]byte, 256),
		DataLength: 256,
		Length:     256,
	})
	if err != nil {
		if q != nil && q.Return == errorFileNotFound {
			return regResult{outcome: regAbsent}
		}
		return regResult{outcome: regError, err: fmt.Errorf("query: %w", err)}
	}
	if q.Type == winreg.RegDword && len(q.Data) >= 4 {
		return regResult{outcome: regPresent, value: binary.LittleEndian.Uint32(q.Data[:4])}
	}
	return regResult{outcome: regError, err: fmt.Errorf("unexpected type=%d len=%d", q.Type, len(q.Data))}
}

// close tears down the named-pipe connection.
func (s *liveWinregSession) close() {
	if s.cc != nil {
		s.cc.Close(s.ctx)
	}
}
