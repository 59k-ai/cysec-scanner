// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// fakeLDAPConn is a canned ldapConn for the off-DC bind-order and attribute-
// mapping tests. It routes RootDSE / base-DN searches via searchFn and the paged
// user enumeration via pageFn.
type fakeLDAPConn struct {
	searchFn func(*ldap.SearchRequest) (*ldap.SearchResult, error)
	pageFn   func(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error)
	closed   bool
}

func (f *fakeLDAPConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if f.searchFn != nil {
		return f.searchFn(r)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeLDAPConn) SearchWithPaging(r *ldap.SearchRequest, n uint32) (*ldap.SearchResult, error) {
	if f.pageFn != nil {
		return f.pageFn(r, n)
	}
	return &ldap.SearchResult{}, nil
}

func (f *fakeLDAPConn) Close() error { f.closed = true; return nil }

func gatedADAsset() payload.AssetItem {
	ip := "10.77.0.10"
	return payload.AssetItem{
		ExternalID: "ip:10.77.0.10",
		IPAddress:  &ip,
		FQDN:       "dc01.lab.cysec.test",
	}
}

// TestBindOrderLDAPSBeforeGSSAPI proves the D-01 bind priority: LDAPS (636) is
// always attempted BEFORE the GSSAPI/389 fallback, and the GSSAPI path is reached
// only when LDAPS is unavailable. An injectable recording dialer captures the
// attempt order; the test fails if the order is reversed or if LDAPS is skipped.
func TestBindOrderLDAPSBeforeGSSAPI(t *testing.T) {
	orig := bindAttempt
	t.Cleanup(func() { bindAttempt = orig })

	cred := scanCredential{domainUser: `LAB\svc`, password: "pw"}

	// Case 1: LDAPS fails -> both attempted, LDAPS FIRST.
	var order []bindMethod
	bindAttempt = func(_ context.Context, m bindMethod, _ ldapTarget, _ scanCredential) (ldapConn, error) {
		order = append(order, m)
		if m == bindLDAPS {
			return nil, errors.New("no ldaps certificate on DC")
		}
		return &fakeLDAPConn{}, nil
	}
	_ = readAD(context.Background(), gatedADAsset(), cred)
	if len(order) != 2 || order[0] != bindLDAPS || order[1] != bindGSSAPI {
		t.Fatalf("bind order = %v, want [ldaps gssapi] (LDAPS must be tried before GSSAPI)", order)
	}

	// Case 2: LDAPS succeeds -> GSSAPI MUST NOT be attempted (LDAPS preferred).
	order = nil
	bindAttempt = func(_ context.Context, m bindMethod, _ ldapTarget, _ scanCredential) (ldapConn, error) {
		order = append(order, m)
		return &fakeLDAPConn{}, nil
	}
	_ = readAD(context.Background(), gatedADAsset(), cred)
	if len(order) != 1 || order[0] != bindLDAPS {
		t.Fatalf("bind order with LDAPS available = %v, want [ldaps] only (GSSAPI must not run when LDAPS binds)", order)
	}
}

// fakeGSSWrapper records how the final SASL token is produced so the wrap-token
// signing can be asserted without a live DC. Unwrap returns a 4-byte SASL caps
// field (offered layers + max buffer); Wrap records the signing request and
// returns a distinguishable SIGNED envelope.
type fakeGSSWrapper struct {
	offered     byte
	maxBuf      [3]byte
	wrapCalls   int
	wrapSeal    bool
	wrapPayload []byte
}

func (w *fakeGSSWrapper) Unwrap(_ []byte) ([]byte, error) {
	return append([]byte{w.offered}, w.maxBuf[:]...), nil
}

func (w *fakeGSSWrapper) Wrap(payload []byte, confidential bool) ([]byte, error) {
	w.wrapCalls++
	w.wrapSeal = confidential
	w.wrapPayload = append([]byte(nil), payload...)
	return append([]byte("SIGNED:"), payload...), nil
}

// TestWrapTokenSignsFinalSaslToken proves the patch: the final SASL negotiation
// token is GSS-WRAPPED (signed/sealed), selecting a confidentiality/integrity
// security layer. The stock go-ldap client hard-codes "no security layer" and
// sends the final token UNSIGNED; this test fails against that behaviour (the RED
// stub returns an unwrapped nil, so Wrap is never called).
func TestWrapTokenSignsFinalSaslToken(t *testing.T) {
	w := &fakeGSSWrapper{offered: saslLayerNone | saslLayerIntegrity | saslLayerConf, maxBuf: [3]byte{0x00, 0x10, 0x00}}
	out, err := negotiateSaslAuthSigned(w, []byte("server-wrap-token"), "")
	if err != nil {
		t.Fatalf("negotiateSaslAuthSigned: %v", err)
	}
	if w.wrapCalls != 1 {
		t.Fatalf("final SASL token was not GSS-wrapped (Wrap calls=%d); the unpatched 'no security layer' path sends it unsigned", w.wrapCalls)
	}
	if !bytes.HasPrefix(out, []byte("SIGNED:")) {
		t.Fatalf("final token is not signed/sealed: %q", out)
	}
	if len(w.wrapPayload) < 4 {
		t.Fatalf("wrapped payload too short: %v", w.wrapPayload)
	}
	if w.wrapPayload[0] != saslLayerConf {
		t.Fatalf("chosen security layer = 0x%02x, want 0x%02x (confidentiality/seal), NOT 'no security layer'", w.wrapPayload[0], saslLayerConf)
	}
	if !w.wrapSeal {
		t.Fatalf("confidentiality offered but seal not requested on the final token")
	}
	if w.wrapPayload[1] != 0x00 || w.wrapPayload[2] != 0x10 || w.wrapPayload[3] != 0x00 {
		t.Fatalf("max receive buffer not echoed into the response: %v", w.wrapPayload[1:4])
	}
}

// TestWrapTokenRefusesNoSecurityLayer proves the patch refuses the stock
// behaviour: when the DC offers ONLY "no security layer", the negotiation errors
// instead of sending an unsigned final token (which a signing-enforced DC would
// reject with "Strong Auth Required" / data 57).
func TestWrapTokenRefusesNoSecurityLayer(t *testing.T) {
	w := &fakeGSSWrapper{offered: saslLayerNone, maxBuf: [3]byte{0x00, 0x10, 0x00}}
	_, err := negotiateSaslAuthSigned(w, []byte("server-wrap-token"), "")
	if err == nil {
		t.Fatal("expected refusal when only 'no security layer' is offered, got nil error")
	}
	if w.wrapCalls != 0 {
		t.Fatalf("must not sign/send a token when refusing; Wrap called %d times", w.wrapCalls)
	}
}

// --- Task 2 helpers (shared by the mapping tests) ---

func intp(i int) *int { return &i }

// adFakeConn returns a fakeLDAPConn that answers the RootDSE defaultNamingContext
// probe, the base-DN password-policy read, and the paged user enumeration.
func adFakeConn(baseDN string, policy map[string][]string, users []map[string][]string) *fakeLDAPConn {
	return &fakeLDAPConn{
		searchFn: func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if r.BaseDN == "" {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					ldap.NewEntry("", map[string][]string{"defaultNamingContext": {baseDN}}),
				}}, nil
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				ldap.NewEntry(baseDN, policy),
			}}, nil
		},
		pageFn: func(_ *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
			entries := make([]*ldap.Entry, 0, len(users))
			for i, u := range users {
				entries = append(entries, ldap.NewEntry("CN=u"+strconv.Itoa(i)+","+baseDN, u))
			}
			return &ldap.SearchResult{Entries: entries}, nil
		},
	}
}
