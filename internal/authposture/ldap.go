// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package authposture

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/59k-ai/cysec-scanner/internal/payload"
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

// userAccountControl ACCOUNTDISABLE bit (MS-ADTS): when set, the account is
// disabled -> IdentityItem.IsActive is false.
const uacAccountDisable = 0x2

// per100nsPerDay is the number of 100-nanosecond intervals in one day
// (10^7 per second * 86400 seconds), the unit AD stores maxPwdAge in.
const per100nsPerDay int64 = 864000000000

// privilegedGroupCNs are the domain-admins-class group RDNs that mark an identity
// as privileged when present in its memberOf. Matched case-insensitively on the
// "cn=<name>" RDN of each memberOf DN.
var privilegedGroupCNs = []string{
	"domain admins", "enterprise admins", "schema admins",
	"administrators", "account operators", "backup operators",
}

// readADEntries reads the domain password policy + identities over a bound
// connection and maps them onto hostFacts. Each read is independent and
// never-raises: a failure lands a per-check note and the other reads still map.
// externalID is the gated host that produced this bind (provenance only; AD
// policy/identities are domain-scoped and carry no asset FK in the v6 schema).
func readADEntries(conn ldapConn, externalID string, hf *hostFacts) {
	_ = externalID
	baseDN, err := readBaseDN(conn)
	if err != nil {
		hf.note(noteKeyLDAP+"_rootdse", err.Error())
		return
	}
	readPasswordPolicy(conn, baseDN, hf)
	readIdentities(conn, baseDN, hf)
}

// readBaseDN reads the domain naming context (search base) from RootDSE.
func readBaseDN(conn ldapConn) (string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("rootdse: %w", err)
	}
	if len(res.Entries) == 0 {
		return "", errors.New("rootdse: no entry")
	}
	dn := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if dn == "" {
		return "", errors.New("rootdse: defaultNamingContext absent")
	}
	return dn, nil
}

// readPasswordPolicy reads the default-domain password policy from the base DN
// (read-only ScopeBaseObject search) and maps it onto one PasswordPolicyItem.
func readPasswordPolicy(conn ldapConn, baseDN string, hf *hostFacts) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"minPwdLength", "pwdProperties", "lockoutThreshold", "maxPwdAge", "pwdHistoryLength"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		hf.note(noteKeyLDAP+"_password_policy", err.Error())
		return
	}
	if len(res.Entries) == 0 {
		hf.note(noteKeyLDAP+"_password_policy", "no base-DN entry")
		return
	}
	e := res.Entries[0]
	hf.passwordPolicies = append(hf.passwordPolicies, payload.PasswordPolicyItem{
		PolicyName:         "Default Domain Policy",
		Scope:              "domain",
		MinLength:          parseOptInt(e.GetAttributeValue("minPwdLength")),
		HistoryLength:      parseOptInt(e.GetAttributeValue("pwdHistoryLength")),
		LockoutThreshold:   parseOptInt(e.GetAttributeValue("lockoutThreshold")),
		MaxAgeDays:         parseMaxPwdAgeDays(e.GetAttributeValue("maxPwdAge")),
		ComplexityRequired: complexityFromPwdProperties(e.GetAttributeValue("pwdProperties")),
		AppliesTo:          []string{},
		EvidenceDN:         baseDN,
	})
}

// readIdentities reads the domain user accounts (paged, read-only whole-subtree
// search) and maps each onto an IdentityItem.
func readIdentities(conn ldapConn, baseDN string, hf *hostFacts) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "userAccountControl", "servicePrincipalName", "memberOf"}, nil)
	res, err := conn.SearchWithPaging(req, identityPageSize)
	if err != nil {
		hf.note(noteKeyLDAP+"_identities", err.Error())
		return
	}
	for _, e := range res.Entries {
		sam := e.GetAttributeValue("sAMAccountName")
		if sam == "" {
			continue
		}
		hf.identities = append(hf.identities, payload.IdentityItem{
			ExternalID:   "ad:" + sam,
			Username:     sam,
			Source:       adIdentitySource,
			IsActive:     isActiveFromUAC(e.GetAttributeValue("userAccountControl")),
			IsPrivileged: isPrivilegedFromMemberOf(e.GetAttributeValues("memberOf")),
		})
	}
}

// parseOptInt parses a decimal AD attribute into *int, nil on empty/unparseable
// (so an unobserved value marshals to JSON null, not a fabricated 0).
func parseOptInt(s string) *int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return &v
}

// parseMaxPwdAgeDays converts AD's maxPwdAge (a signed 64-bit 100-nanosecond
// interval, stored negative) into whole days. It is the WINAD-04 precision edge:
// no overflow, no sign loss, and a zero / never-expires (Int64 min) / unparseable
// value yields a NULL pointer (JSON null), never 0.
func parseMaxPwdAgeDays(s string) *int {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	// 0 = no maximum; math.MinInt64 (0x8000000000000000) = "never expires".
	if v == 0 || v == math.MinInt64 {
		return nil
	}
	mag := v
	if mag < 0 {
		mag = -mag // safe: v != math.MinInt64, so negation does not overflow
	}
	days := int(mag / per100nsPerDay)
	return &days
}

// complexityFromPwdProperties maps the pwdProperties DOMAIN_PASSWORD_COMPLEX bit
// (0x1) to a *bool; nil when pwdProperties is absent/unparseable.
func complexityFromPwdProperties(s string) *bool {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	b := v&0x1 != 0
	return &b
}

// isActiveFromUAC derives IsActive from the userAccountControl ACCOUNTDISABLE bit
// (0x2 set -> disabled). An absent/unparseable UAC assumes active (the scanner
// emits evidence; it never fabricates a disabled account).
func isActiveFromUAC(s string) bool {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return true
	}
	return v&uacAccountDisable == 0
}

// isPrivilegedFromMemberOf reports whether any memberOf DN names a privileged
// (domain-admins-class) group, matched on the lowercased "cn=<name>" RDN.
func isPrivilegedFromMemberOf(memberOf []string) bool {
	for _, dn := range memberOf {
		low := strings.ToLower(dn)
		for _, g := range privilegedGroupCNs {
			if strings.Contains(low, "cn="+g) {
				return true
			}
		}
	}
	return false
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
