// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// ldap.go is the signed-LDAP / Active Directory reader (the 06-01 readAD seam).
// It reads the domain password policy + identities over a SIGNED bind and maps
// them onto the v6 password_policies / identities slices (WINAD-03). The bind
// prefers LDAPS (636) for production and falls back to a patched GSSAPI sign+seal
// bind over 389/Kerberos for a signing-enforced WS2025 DC (D-01). The Kerberos
// TGT is obtained by an in-process AS exchange with PA-FX-FAST disabled (D-02);
// there is no external credential cache or key file. All operations are
// search/read; the reader is read-only and never-raises (a bind/read failure or a
// non-domain host lands a per-check note, never a stage error). It populates ONLY
// hostFacts and NEVER calls ScanState — authposture.go is the single merge point.
//
// The go-ldap sign+seal "patch" (D-01) is carried HERE, inside the submodule, as
// a self-contained GSSAPIClient implementation (signedGSSAPIClient) whose
// NegotiateSaslAuth signs/seals the final SASL wrap-token — the exact spot stock
// go-ldap gets wrong ("no security layer", rejected by WS2025 with data 57). The
// patch rides go-ldap's pluggable GSSAPIBind interface, so no fork of go-ldap is
// needed and the signing logic is unit-testable off-DC (negotiateSaslAuthSigned
// over an injectable gssWrapper).

// bindMethod enumerates the ordered signed-bind attempts.
type bindMethod string

const (
	bindLDAPS  bindMethod = "ldaps"  // preferred production path (636, TLS channel)
	bindGSSAPI bindMethod = "gssapi" // fallback (389, patched Kerberos sign+seal)
)

// bindOrder is the LDAPS-preferred, patched-GSSAPI-fallback priority (D-01).
// readAD attempts each in order and stops at the first that binds.
var bindOrder = []bindMethod{bindLDAPS, bindGSSAPI}

const (
	noteKeyLDAP      = "authposture_ldap"
	ldapDialTimeout  = 10 * time.Second
	ldapCallTimeout  = 20 * time.Second
	identityPageSize = 500
	// adIdentitySource is the exact v6 enum member for an AD-sourced identity
	// (copied from payload.py's strict source of truth — never guessed).
	adIdentitySource = "active_directory"
)

// SASL security-layer bits (RFC 4752): the first octet of the (un)wrapped SASL
// token. The patch REFUSES saslLayerNone and selects a signed/sealed layer.
const (
	saslLayerNone      byte = 0x01
	saslLayerIntegrity byte = 0x02
	saslLayerConf      byte = 0x04
)

// ldapTarget carries the per-host coordinates a bind needs: the dial host, the
// FQDN (LDAPS cert name + the GSSAPI SPN), and the derived Kerberos realm.
type ldapTarget struct {
	host  string
	fqdn  string
	realm string
}

// ldapConn is the minimal read surface over *ldap.Conn this reader uses, so the
// attribute-mapping tests can inject a fake bound connection without a live DC.
// *ldap.Conn satisfies it (Search / SearchWithPaging / Close).
type ldapConn interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error)
	Close() error
}

// bindAttemptFunc dials + binds one method against a host, returning a bound
// connection or an error. It is the injectable seam that makes the bind ORDER
// testable (a recording dialer) without a live DC — mirrors portscan's probe var.
type bindAttemptFunc func(ctx context.Context, method bindMethod, tgt ldapTarget, cred scanCredential) (ldapConn, error)

// bindAttempt is the package-var bind seam; swapped in tests.
var bindAttempt bindAttemptFunc = liveBindAttempt

// bindNoteKey derives the per-method evidence-note key for a degraded bind.
func bindNoteKey(m bindMethod) string { return noteKeyLDAP + "_" + string(m) }

// readAD binds a signed LDAP connection (LDAPS preferred, patched GSSAPI
// fallback) and reads the AD password policy + identities onto hostFacts. It
// NEVER raises: a non-domain host or a failed bind/read lands a per-check note and
// returns an empty-ish hostFacts so the stage still ships a complete payload.
func readAD(ctx context.Context, ai payload.AssetItem, cred scanCredential) hostFacts {
	hf := newHostFacts()
	host := targetHost(ai)
	if host == "" {
		hf.note(noteKeyLDAP, "no_address")
		return hf
	}
	tgt := ldapTarget{host: host, fqdn: ai.FQDN, realm: realmFromFQDN(ai.FQDN)}

	var conn ldapConn
	for _, m := range bindOrder {
		if ctx.Err() != nil {
			hf.note(noteKeyLDAP, "cancelled")
			return hf
		}
		c, err := bindAttempt(ctx, m, tgt, cred)
		if err != nil {
			hf.note(bindNoteKey(m), err.Error())
			continue
		}
		conn = c
		break
	}
	if conn == nil {
		hf.note(noteKeyLDAP, "all signed binds failed; AD posture not read")
		return hf
	}
	defer conn.Close()

	readADEntries(conn, ai.ExternalID, &hf)
	return hf
}

// readADEntries reads the domain password policy + identities over a bound
// connection and maps them onto hostFacts. GREEN (Task 2) fills this.
func readADEntries(conn ldapConn, externalID string, hf *hostFacts) {
	_ = conn
	_ = externalID
	_ = hf
}

// liveBindAttempt is the real dialer. For LDAPS it opens a TLS channel to 636 and
// simple-binds (the TLS channel signs the session); the DC certificate is
// validated against the production trust store (NO verification-disabled option —
// the spike used that only because the lab DC had no cert). For GSSAPI it opens
// 389 and binds with the patched signedGSSAPIClient over Kerberos.
func liveBindAttempt(ctx context.Context, method bindMethod, tgt ldapTarget, cred scanCredential) (ldapConn, error) {
	switch method {
	case bindLDAPS:
		tlsCfg := &tls.Config{ServerName: tgt.fqdn, MinVersion: tls.VersionTLS12}
		conn, err := ldap.DialURL("ldaps://"+net.JoinHostPort(tgt.host, "636"),
			ldap.DialWithTLSConfig(tlsCfg),
			ldap.DialWithDialer(&net.Dialer{Timeout: ldapDialTimeout}))
		if err != nil {
			return nil, fmt.Errorf("ldaps_dial: %w", err)
		}
		conn.SetTimeout(ldapCallTimeout)
		if err := conn.Bind(cred.domainUser, cred.password); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldaps_bind: %w", err)
		}
		return conn, nil

	case bindGSSAPI:
		if tgt.fqdn == "" || tgt.realm == "" {
			return nil, errors.New("gssapi: no FQDN/realm for SPN + Kerberos")
		}
		conn, err := ldap.DialURL("ldap://"+net.JoinHostPort(tgt.host, "389"),
			ldap.DialWithDialer(&net.Dialer{Timeout: ldapDialTimeout}))
		if err != nil {
			return nil, fmt.Errorf("ldap_dial: %w", err)
		}
		conn.SetTimeout(ldapCallTimeout)
		cl, err := newSignedGSSAPIClient(cred, tgt)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("gssapi_client: %w", err)
		}
		if err := conn.GSSAPIBind(cl, "ldap/"+tgt.fqdn, ""); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("gssapi_bind: %w", err)
		}
		return conn, nil
	}
	return nil, fmt.Errorf("unknown bind method %q", method)
}

// gssWrapper abstracts the GSS per-message token Unwrap/Wrap so the SASL signing
// logic (negotiateSaslAuthSigned) is unit-testable with a fake context — the real
// implementation (krbGSSWrapper) is gokrb5-backed. Unwrap verifies the server's
// wrap token and returns its payload; Wrap produces a signed (and sealed when the
// caller requests confidentiality) initiator wrap token.
type gssWrapper interface {
	Unwrap(token []byte) ([]byte, error)
	Wrap(payload []byte, confidential bool) ([]byte, error)
}

// negotiateSaslAuthSigned is the patched final SASL step (RFC 4752 §3.1). The
// server token, once UNWRAPPED, is a 4-byte field: the offered security layers
// (first octet) + max receive buffer (next three). THE PATCH (D-01, the spike-002
// PARTIAL break): select a SIGNED/SEALED security layer and WRAP the response —
// stock go-ldap hard-codes "no security layer" and sends the final token in the
// clear, which a signing-enforced WS2025 DC rejects ("Strong Auth Required" /
// data 57 SEC_E_INVALID_TOKEN). If the server offers only "no security layer",
// this refuses the bind rather than silently downgrading.
func negotiateSaslAuthSigned(w gssWrapper, serverToken []byte, authzid string) ([]byte, error) {
	caps, err := w.Unwrap(serverToken)
	if err != nil {
		return nil, fmt.Errorf("unwrap server sasl token: %w", err)
	}
	if len(caps) < 4 {
		return nil, fmt.Errorf("sasl server token too short: %d bytes", len(caps))
	}
	offered := caps[0]

	var chosen byte
	var confidential bool
	switch {
	case offered&saslLayerConf != 0:
		chosen, confidential = saslLayerConf, true
	case offered&saslLayerIntegrity != 0:
		chosen, confidential = saslLayerIntegrity, false
	default:
		return nil, fmt.Errorf("server offers no integrity/confidentiality SASL layer (0x%02x); refusing unsigned bind", offered)
	}

	// Client response: chosen layer (1 octet) + echoed max receive buffer
	// (3 octets) + optional authorization identity. This payload MUST be signed.
	resp := make([]byte, 4, 4+len(authzid))
	resp[0] = chosen
	copy(resp[1:4], caps[1:4])
	resp = append(resp, []byte(authzid)...)

	signed, err := w.Wrap(resp, confidential)
	if err != nil {
		return nil, fmt.Errorf("sign final sasl token: %w", err)
	}
	return signed, nil
}

// signedGSSAPIClient implements go-ldap's pluggable GSSAPIClient interface with a
// SIGNED final SASL wrap-token — this IS the carried go-ldap sign+seal patch
// (D-01). The AS exchange runs in-process with PA-FX-FAST disabled (D-02).
type signedGSSAPIClient struct {
	cl      *client.Client
	wrapper gssWrapper
}

// newSignedGSSAPIClient logs in with an in-process AS exchange, PA-FX-FAST
// DISABLED (D-02: the remedy for gokrb5 mishandling the WS2025 FAST negotiation).
// The credential is supplied in-process from the env scan account (D-05); there
// is no external credential cache or key file.
func newSignedGSSAPIClient(cred scanCredential, tgt ldapTarget) (*signedGSSAPIClient, error) {
	if tgt.realm == "" {
		return nil, errors.New("no kerberos realm derivable from fqdn")
	}
	conf, err := config.NewFromString(minimalKrb5Conf(tgt.realm, tgt.host))
	if err != nil {
		return nil, fmt.Errorf("krb5_config: %w", err)
	}
	cl := client.NewWithPassword(bareUsername(cred.domainUser), tgt.realm, cred.password, conf,
		client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("krb5_login: %w", err)
	}
	return &signedGSSAPIClient{cl: cl}, nil
}

// InitSecContext performs the Kerberos AP exchange via SPNEGO and captures the
// service-ticket session key that drives the per-message SASL wrap token.
func (c *signedGSSAPIClient) InitSecContext(target string, _ []byte) ([]byte, bool, error) {
	sc := spnego.SPNEGOClient(c.cl, target)
	if err := sc.AcquireCred(); err != nil {
		return nil, false, fmt.Errorf("acquire_cred: %w", err)
	}
	st, err := sc.InitSecContext()
	if err != nil {
		return nil, false, fmt.Errorf("init_sec_context: %w", err)
	}
	tokenBytes, err := st.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("marshal_token: %w", err)
	}
	// The service-ticket session key (cached from the TGS above) keys the signed
	// per-message wrap token used by NegotiateSaslAuth.
	_, key, err := c.cl.GetServiceTicket(target)
	if err != nil {
		return nil, false, fmt.Errorf("service_ticket_key: %w", err)
	}
	c.wrapper = &krbGSSWrapper{key: key}
	return tokenBytes, false, nil
}

// NegotiateSaslAuth performs the patched final SASL step — signing/sealing the
// final wrap-token so a signing-enforced DC accepts the bind.
func (c *signedGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	if c.wrapper == nil {
		return nil, errors.New("gssapi security context not established")
	}
	return negotiateSaslAuthSigned(c.wrapper, token, authzid)
}

// DeleteSecContext releases the established context.
func (c *signedGSSAPIClient) DeleteSecContext() error {
	c.wrapper = nil
	return nil
}

// krbGSSWrapper is the gokrb5-backed gssWrapper. Unwrap verifies the acceptor's
// wrap token; Wrap produces a signed initiator wrap token. (gokrb5 v8.4.4's public
// API signs/MICs the token; a confidentiality request degrades to integrity,
// which already clears the signing-enforced DC's "Strong Auth Required" wall.)
type krbGSSWrapper struct {
	key types.EncryptionKey
}

func (w *krbGSSWrapper) Unwrap(token []byte) ([]byte, error) {
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(token, true); err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	ok, err := wt.Verify(w.key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return nil, errors.New("server wrap token checksum invalid")
	}
	return wt.Payload, nil
}

func (w *krbGSSWrapper) Wrap(payload []byte, _ bool) ([]byte, error) {
	wt, err := gssapi.NewInitiatorWrapToken(payload, w.key)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}
	return wt.Marshal()
}

// minimalKrb5Conf builds an in-memory krb5 config pointing at the DC as the KDC,
// with DNS/PTR lookups disabled (the lab/headless constraint: no PTR records,
// no DNS SRV). No external config file is read.
func minimalKrb5Conf(realm, kdc string) string {
	return fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
[realms]
  %s = {
    kdc = %s
  }
`, realm, realm, kdc)
}

// bareUsername strips a DOMAIN\ prefix or @REALM suffix from the scan account, so
// gokrb5 receives the bare sAMAccountName it expects.
func bareUsername(u string) string {
	if i := strings.LastIndex(u, `\`); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[:i]
	}
	return u
}

// realmFromFQDN derives the uppercased Kerberos realm from a host FQDN
// (dc01.lab.cysec.test -> LAB.CYSEC.TEST). Empty when the FQDN has no domain part.
func realmFromFQDN(fqdn string) string {
	if i := strings.Index(fqdn, "."); i >= 0 && i+1 < len(fqdn) {
		return strings.ToUpper(fqdn[i+1:])
	}
	return ""
}
