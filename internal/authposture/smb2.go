// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/59k-ai/cysec-scanner/internal/payload"
)

// smb2.go is the live, READ-ONLY SMB2 negotiate probe plus the registry+probe
// combiner for the effective-signing verdict. A registry-only SMB-signing verdict
// false-negatives Win11 24H2+ (where LanmanServer requiresecuritysignature is
// absent-by-default while signing is effectively required), so the live negotiate
// probe is mandatory (WINAD-02). The probe performs ONLY the SMB2 NEGOTIATE
// exchange to TCP 445 (no authenticated session, no tree connect, no file op),
// reads the server's advertised SecurityMode (signing enabled/required), and
// parses it with a strictly bounded parser that collapses any malformed/truncated/
// hostile response to an empty result — it never hangs, over-reads, or panics.
// The combiner folds the probe into the Task-1 registry read; a probe failure
// degrades to the registry-only rows plus a per-check note (never a stage error).

const (
	smb2Port = "445"
	// smb2DialTimeout / smb2IOTimeout bound the client handshake so a dead or
	// filtered host fails fast rather than hanging the bounded host pool.
	smb2DialTimeout = 5 * time.Second
	smb2IOTimeout   = 5 * time.Second
	// smb2MaxResponse caps the framed negotiate response read (defence against a
	// hostile server advertising a huge length). A real negotiate response is well
	// under this.
	smb2MaxResponse = 4096

	// SMB2 header length and the NEGOTIATE command id.
	smb2HeaderLen        = 64
	smb2NegotiateCommand = 0x0000

	// Server SecurityMode flags in the NEGOTIATE response (MS-SMB2 2.2.4).
	smb2SigningEnabled  = 0x0001 // SMB2_NEGOTIATE_SIGNING_ENABLED
	smb2SigningRequired = 0x0002 // SMB2_NEGOTIATE_SIGNING_REQUIRED

	// Effective-signing verdict markers (evidence, not a compliance verdict).
	effectiveRequired    = "required"
	effectiveNotRequired = "not_required"
	effectiveUnknown     = "unknown"

	checkCodeEffectiveSigning = "smb_signing:effective"
)

// errSMB2Bounded is returned when a framed response declares a length outside the
// accepted bound (collapsed to an empty probe result).
var errSMB2Bounded = errors.New("smb2 response length out of bounds")

// smb2SigningProbe is the parsed result of a read-only SMB2 NEGOTIATE probe. ok is
// false when no well-formed negotiate response could be read/parsed (the combiner
// then degrades to the registry-only rows).
type smb2SigningProbe struct {
	ok              bool
	signingEnabled  bool
	signingRequired bool
}

// smb2ProbeFunc is the injectable probe seam. Tests swap it for a canned result;
// production uses liveProbeSMB2.
type smb2ProbeFunc func(ctx context.Context, host string) smb2SigningProbe

// probeSMB2 is the package-var probe seam the combiner calls; swapped in tests.
var probeSMB2 smb2ProbeFunc = liveProbeSMB2

// liveProbeSMB2 performs a bounded, read-only SMB2 NEGOTIATE exchange to TCP 445
// and returns the server's advertised signing flags. It is strictly outbound /
// client-side: no authenticated session, no tree connect, no file operation. Any
// dial / write / read / parse failure collapses to an empty (ok=false) result —
// never a panic, never a stage error.
func liveProbeSMB2(ctx context.Context, host string) smb2SigningProbe {
	d := net.Dialer{Timeout: smb2DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, smb2Port))
	if err != nil {
		return smb2SigningProbe{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smb2IOTimeout))
	if _, err := conn.Write(negotiateRequest()); err != nil {
		return smb2SigningProbe{}
	}
	msg, err := readFramedSMB2(conn)
	if err != nil {
		return smb2SigningProbe{}
	}
	return parseNegotiateResponse(msg)
}

// negotiateRequest builds a minimal SMB2 NEGOTIATE request (dialects 2.0.2 .. 3.0.2)
// framed with the 4-byte direct-TCP transport header. It offers client
// signing-enabled; the server's advertised SecurityMode is what the probe reads
// back. Dialect 3.1.1 is deliberately NOT offered (it would require negotiate
// contexts); a 3.0.2-max request still yields the server SecurityMode.
func negotiateRequest() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}

	body := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(body[0:], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(body[4:], smb2SigningEnabled)    // SecurityMode (client)
	// body[6:8] Reserved, body[8:12] Capabilities, body[12:28] ClientGuid,
	// body[28:36] ClientStartTime all remain zero.
	off := 36
	for _, dl := range dialects {
		binary.LittleEndian.PutUint16(body[off:], dl)
		off += 2
	}

	hdr := make([]byte, smb2HeaderLen)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(hdr[4:], 64)                       // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:], smb2NegotiateCommand)    // Command = NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[14:], 1)                       // CreditRequest

	msg := append(hdr, body...)

	frame := make([]byte, 4+len(msg))
	// Direct-TCP transport header: 1 zero byte + 3-byte big-endian length.
	frame[0] = 0
	frame[1] = byte(len(msg) >> 16)
	frame[2] = byte(len(msg) >> 8)
	frame[3] = byte(len(msg))
	copy(frame[4:], msg)
	return frame
}

// readFramedSMB2 reads ONE length-prefixed SMB2 message (4-byte direct-TCP
// transport header: 1 reserved byte + 3-byte big-endian length), STRICTLY bounded
// by smb2MaxResponse so a hostile length can neither allocate unbounded memory nor
// block indefinitely (the deadline is set by the caller).
func readFramedSMB2(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > smb2MaxResponse {
		return nil, errSMB2Bounded
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// parseNegotiateResponse extracts the server SecurityMode from an SMB2 message
// (header + body, transport already stripped). It is STRICTLY BOUNDED: every read
// is length-checked, there is no loop, and any malformed / truncated / non-negotiate
// input collapses to an empty (ok=false) result — never an over-read or panic.
func parseNegotiateResponse(msg []byte) smb2SigningProbe {
	// SecurityMode lives at NEGOTIATE-response body offset 2, i.e. absolute offset
	// smb2HeaderLen+2. Require the full 2-byte field to be present.
	const securityModeOffset = smb2HeaderLen + 2
	if len(msg) < securityModeOffset+2 {
		return smb2SigningProbe{}
	}
	if msg[0] != 0xFE || msg[1] != 'S' || msg[2] != 'M' || msg[3] != 'B' {
		return smb2SigningProbe{}
	}
	if binary.LittleEndian.Uint16(msg[12:14]) != smb2NegotiateCommand {
		return smb2SigningProbe{}
	}
	secMode := binary.LittleEndian.Uint16(msg[securityModeOffset : securityModeOffset+2])
	return smb2SigningProbe{
		ok:              true,
		signingEnabled:  secMode&smb2SigningEnabled != 0,
		signingRequired: secMode&smb2SigningRequired != 0,
	}
}

// effectiveSigningCheck combines the Task-1 registry server-signing result with
// the live SMB2 negotiate probe into ONE effective-signing configuration_checks
// row, so a modern client (server-signing value absent-by-default yet signing
// effectively required) is NOT false-negatived: a probe that reports
// signing-required ALWAYS resolves the effective verdict to required, regardless
// of an absent/0 registry value. Evidence from BOTH sources is recorded; the
// scanner emits evidence only, never the compliance verdict.
//
func effectiveSigningCheck(externalID string, serverReq regResult, haveServerReq bool, probe smb2SigningProbe) payload.ConfigurationCheckItem {
	effective := effectiveUnknown
	var evidence []string

	// Registry signal (LanmanServer requiresecuritysignature). An ABSENT value is
	// the OS default and is NOT treated as not-required (tri-state preserved); the
	// probe resolves it below.
	if haveServerReq {
		switch serverReq.outcome {
		case regPresent:
			evidence = append(evidence, "registry_requiresecuritysignature="+strconv.FormatUint(uint64(serverReq.value), 10))
			if serverReq.value != 0 {
				effective = effectiveRequired
			} else {
				effective = effectiveNotRequired
			}
		case regAbsent:
			evidence = append(evidence, "registry_requiresecuritysignature="+observedAbsent)
		default:
			evidence = append(evidence, "registry_requiresecuritysignature="+observedError)
		}
	}

	// Live SMB2 negotiate probe. A probe reporting signing-required ALWAYS resolves
	// the effective verdict to required — this is what prevents the registry-only
	// false-negative on a modern client (absent-by-default yet required). When the
	// probe reports not-required and the registry gave no definite "required", the
	// effective verdict settles to not-required.
	if probe.ok {
		evidence = append(evidence,
			"smb2_signing_required="+strconv.FormatBool(probe.signingRequired),
			"smb2_signing_enabled="+strconv.FormatBool(probe.signingEnabled))
		if probe.signingRequired {
			effective = effectiveRequired
		} else if effective != effectiveRequired {
			effective = effectiveNotRequired
		}
	}

	return payload.ConfigurationCheckItem{
		AssetExternalID: externalID,
		CheckCode:       checkCodeEffectiveSigning,
		Title:           "Effective SMB signing (registry + live SMB2 negotiate)",
		Status:          checkStatusCollected,
		Severity:        severityInfo,
		ObservedValue:   effective + " [" + strings.Join(evidence, ";") + "]",
	}
}
