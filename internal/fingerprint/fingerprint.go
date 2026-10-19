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

	scannerdata "github.com/59k-ai/cysec-scanner"
	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/fingerprint/osfp"
	"github.com/59k-ai/cysec-scanner/internal/fingerprint/recog"
	"github.com/59k-ai/cysec-scanner/internal/governance"
	"github.com/59k-ai/cysec-scanner/internal/payload"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
)

// sourceRecogV1 is the provenance label this stage stamps on a service identity
// promoted from a service-fingerprint-database match.
const sourceRecogV1 = "recog-v1"

// confidenceCut is the prefer-unknown confidence cut (inclusive): a match with
// confidence >= cut is promoted as authoritative; below the cut the structured
// identity is suppressed rather than shown as a weak claim (FPRINT-03, D-07).
const confidenceCut = 0.5

// sourcePortBannerV1 is the provenance label for a retained light-parse
// product/version value the service-fingerprint database did NOT promote. The
// port stage's light parse is the only stage that sets product/version without a
// wire source, so a retained (un-promoted) value is a port-banner-v1 value.
const sourcePortBannerV1 = "port-banner-v1"

// confidencePortBannerV1 is the below-cut numeric confidence stamped on a retained
// light-parse value — the honest worth of a light parse (the same "low" magnitude
// the port stage records on its evidence map, below the prefer-unknown cut). It
// pairs the retained value with a source + confidence on the wire (FPRINT-03)
// without ever promoting it to authoritative (D-07).
const confidencePortBannerV1 = 0.3

// sshDBPath is one embedded, governed service-fingerprint database file. It is
// the allowlist entry this stage reads the shared pinned DB version from (every
// vendored Recog file shares one upstream snapshot — FPRINT-04).
const sshDBPath = "data/recog/ssh_banners.xml"

// recogDir is the embedded directory tree of vendored, governed Recog databases
// (one file per protocol). The stage loads the whole corpus so a captured banner
// is routed to the database for its own protocol.
const recogDir = "data/recog"

// Classification-evidence keys the OS engine reads off the asset. They match the
// keys the earlier discovery and port stages write (the coarse reply-TTL family
// and the banner-derived OS cue), so the OS guess reuses evidence already on the
// asset without a second probe.
const (
	evidenceKeyOSTTLFamily = "os_ttl_family"
	evidenceKeyBannerOSCue = "banner_os_cue"
	evidenceKeyOUIVendor   = "oui_vendor"
)

// recogProtocolByPort maps a well-known port to the Recog protocol (the database
// file's declared protocol attribute) its banner should be matched against. A
// port absent from the map is not routed to a service-fingerprint database.
var recogProtocolByPort = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	465:  "smtp",
	587:  "smtp",
	80:   "http",
	443:  "http",
	8008: "http",
	8080: "http",
	8443: "http",
	110:  "pop3",
	995:  "pop3",
	143:  "imap",
	993:  "imap",
}

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

// httpServerRe captures the value of the first Server header in a full HTTP
// response block (status line + header lines), matched line-by-line in
// case-insensitive multiline mode. The service-fingerprint database for http
// matches the Server value, not the whole response block, so the value must be
// extracted before the match. RE2 (linear-time) only — the response block is
// untrusted but already byte-capped and control-char-stripped upstream (D-14).
var httpServerRe = regexp.MustCompile(`(?im)^Server:\s*(.+)$`)

// numericStatusLeaderRe matches the 3-digit status leader a line-oriented text
// protocol prepends to its greeting (e.g. the FTP/SMTP "220 " ready line, or the
// SMTP "220-" multiline-continuation form). The fingerprint databases match the
// payload after the leader, so the "NNN[ -]" prefix is stripped before the match.
// RE2 only, anchored at the start — linear-time on the already-bounded banner.
var numericStatusLeaderRe = regexp.MustCompile(`^\d{3}[ -]`)

// Run executes the fingerprint stage over the accumulator's assets. It returns
// nil on any degraded condition (no assets, database load failure, cancellation)
// so a fully-degraded run still yields a complete, strict-valid payload.
func Run(ctx context.Context, st *scanstate.ScanState, caps capabilities.Capabilities, opts Options) error {
	_ = caps // capabilities reserved for later privileged probe paths

	corpus, err := recog.LoadCorpus(scannerdata.DataFS, recogDir)
	if err != nil {
		// Never-raises: a database that cannot load degrades the stage to a no-op.
		return nil
	}

	// Record the pinned database versions once per run (FPRINT-04): the service
	// fingerprint DB version read from the governed data manifest, and the
	// self-authored OS signature DB version (a package constant).
	if v := recogDBVersion(); v != "" {
		st.SetRecogDBVersion(v)
	}
	st.SetOSSignatureDBVersion(osfp.OSSignatureDBVersion)

	sigs := osfp.DefaultSignatures()

	for _, a := range st.Assets() {
		if ctx.Err() != nil {
			return nil
		}
		banners := st.ServiceBanners(a.ExternalID)
		st.UpdateAsset(a.ExternalID, func(ai *payload.AssetItem) {
			// Service identity: route each captured banner to the database for its
			// own protocol and promote a >=cut match (D-11). Collect any OS cue the
			// matched fingerprint carries to feed the OS engine.
			bannerOSCue := ""
			for i := range ai.Services {
				// Every non-promoted service must still reach the provenance backfill
				// below, so the no-banner and Recog-miss paths fall through rather than
				// short-circuit early — a below-cut or missing match leaves the
				// light-parse value in place and the tail backfill pairs it with its
				// source + confidence on the wire.
				promoted := false
				if banner, ok := banners[ai.Services[i].Port]; ok && banner != "" {
					if id, matched := matchService(corpus, ai.Services[i].Port, banner); matched {
						// Only an at/above-cut match may contribute its OS family: a
						// below-cut service match (e.g. a low-preference mail-greeting
						// database) must not amplify its OS family past the prefer-unknown
						// cut into an os_guess.
						if bannerOSCue == "" && id.OSFamily != "" && id.Confidence >= confidenceCut {
							bannerOSCue = id.OSFamily
						}
						promoted = applyServiceIdentity(&ai.Services[i], id, confidenceCut)
					}
				}
				if !promoted {
					// Miss, below-cut, or no banner: a retained light-parse value keeps
					// its value (never nulled, D-11) and gains its paired provenance.
					backfillPhase4Provenance(&ai.Services[i])
				}
			}

			// OS guess: score the self-authored signatures against the unprivileged
			// evidence already on the asset — the discovery reply-TTL family and the
			// banner OS cue — and emit a guess only at or above the prefer-unknown
			// cut; below it, os_guess / source / confidence stay null together.
			applyOSGuess(ai, sigs, bannerOSCue)

			// Fragile-device gate (FPRINT-05): the SINGLE predicate the later
			// privileged OS stack-probing MUST consult before any intrusive probe.
			// That intrusive path is EMPTY this phase (the stage is passive, and the
			// TTL/banner os_guess above is deliberately NOT gated), so the gate has
			// nothing to suppress yet — it is wired here so Phase-of-privileged-capture
			// plugs its stack probe straight into this decision, overridable via
			// --probe-fragile (opts.ProbeFragile).
			if !shouldSkipIntrusiveProbe(ai.AssetType, ouiVendorFor(ai), opts.ProbeFragile) {
				// Intrusive OS stack probe plugs in here (privileged-capture seam).
			}
		})
	}
	return nil
}

// matchService routes a captured banner to the Recog database for the port's
// protocol and returns the match. The raw banner the port stage captures is the
// wire greeting (a full HTTP response block, or a leadered line-protocol
// greeting), but each fingerprint database matches the normalised PAYLOAD; so the
// banner is run through normalizeBanner for its protocol first. An unrouted port,
// an absent protocol database, or an empty normalised result is a clean miss.
func matchService(corpus *recog.Corpus, port int, banner string) (recog.Identity, bool) {
	proto := recogProtocolByPort[port]
	if proto == "" {
		return recog.Identity{}, false
	}
	db := corpus.DatabaseForProtocol(proto)
	if db == nil {
		return recog.Identity{}, false
	}
	norm := normalizeBanner(proto, banner)
	if norm == "" {
		return recog.Identity{}, false
	}
	return db.Match(norm)
}

// normalizeBanner maps a raw wire banner to the payload the fingerprint database
// for proto matches against. Each protocol greets with its own envelope: ssh
// sends an identification string, http returns a full response block whose Server
// header carries the product, and the line-oriented mail/transfer protocols
// prepend a status leader to their greeting. An unlisted protocol (telnet and the
// default) matches the raw banner unchanged — those databases match the bare
// greeting. An empty result is a clean miss (handled by matchService).
func normalizeBanner(proto, banner string) string {
	switch proto {
	case "ssh":
		return sshComment(banner)
	case "http":
		return httpServerHeader(banner)
	case "ftp", "smtp":
		return stripNumericStatusLeader(banner)
	case "pop3":
		return stripTokenLeader(banner, "+OK", "-ERR")
	case "imap":
		return stripImapLeader(banner)
	default:
		// telnet and any unlisted protocol match the bare greeting (no leader).
		return banner
	}
}

// httpServerHeader returns the trimmed value of the first Server header in a full
// HTTP response block, or "" when the block carries no Server header.
func httpServerHeader(banner string) string {
	m := httpServerRe.FindStringSubmatch(banner)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// stripNumericStatusLeader removes a leading 3-digit status code and its trailing
// space or hyphen (e.g. "220 " or the multiline "220-") from a line-protocol
// greeting, returning the payload the fingerprint database matches. A banner with
// no such leader is returned unchanged.
func stripNumericStatusLeader(banner string) string {
	if numericStatusLeaderRe.MatchString(banner) {
		return banner[4:]
	}
	return banner
}

// stripTokenLeader removes a leading status token (e.g. the POP3 "+OK" / "-ERR")
// and its single following space from a greeting, returning the payload the
// fingerprint database matches. A greeting beginning with none of the tokens is
// returned unchanged. Plain anchored prefix comparison — linear-time, no regex
// engine and so no backtracking of any kind (D-14).
func stripTokenLeader(banner string, tokens ...string) string {
	for _, tok := range tokens {
		prefix := tok + " "
		if strings.HasPrefix(banner, prefix) {
			return banner[len(prefix):]
		}
	}
	return banner
}

// stripImapLeader removes a leading IMAP untagged-response leader — "* OK ",
// "* PREAUTH ", or the bare "* " — from a greeting, returning the payload the
// fingerprint database matches. A greeting that is not an untagged response is
// returned unchanged. Plain anchored prefix comparison — linear-time, no regex
// engine (D-14).
func stripImapLeader(banner string) string {
	const untagged = "* "
	if !strings.HasPrefix(banner, untagged) {
		return banner
	}
	rest := banner[len(untagged):]
	for _, status := range []string{"OK ", "PREAUTH "} {
		if strings.HasPrefix(rest, status) {
			return rest[len(status):]
		}
	}
	return rest
}

// applyOSGuess builds an Observation from the asset's unprivileged evidence (the
// discovery reply-TTL family supplied as its public initial-TTL default, plus a
// banner-derived OS cue) and writes an os_guess / os_guess_source /
// os_guess_confidence trio only when the engine's confidence meets the cut. Below
// the cut it leaves all three null ("unknown"). It never re-probes and never
// feeds any compliance verdict (D-15) — the guess is evidence only.
func applyOSGuess(ai *payload.AssetItem, sigs []osfp.OSSignature, bannerOSCue string) {
	family := evidenceValue(ai, evidenceKeyOSTTLFamily)
	if bannerOSCue == "" {
		bannerOSCue = evidenceValue(ai, evidenceKeyBannerOSCue)
	}
	obs := osfp.Observation{
		ReplyTTL:    osfp.TTLForFamily(family),
		BannerOSCue: bannerOSCue,
	}
	label, source, confidence := osfp.Guess(obs, sigs)
	if label == "" || confidence < confidenceCut {
		return
	}
	g := label
	s := source
	c := confidence
	ai.OSGuess = &g
	ai.OSGuessSource = &s
	ai.OSGuessConfidence = &c
}

// evidenceValue reads one key from the asset's classification evidence map,
// nil-safe, returning "" when the classification, map, or key is absent.
func evidenceValue(ai *payload.AssetItem, key string) string {
	if ai == nil || ai.Classification == nil || ai.Classification.Evidence == nil {
		return ""
	}
	return ai.Classification.Evidence[key]
}

// ouiVendorFor returns the OUI vendor the port stage already resolved for the
// asset (stored lowercased in the classification evidence), so the fragile-device
// gate reuses it without re-probing. It is "" when no vendor was resolved.
func ouiVendorFor(ai *payload.AssetItem) string {
	return evidenceValue(ai, evidenceKeyOUIVendor)
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

// backfillPhase4Provenance pairs a retained light-parse value with its provenance
// on the wire: when a service carries a product or version but no wire-level
// source (the shape the port stage's light parse leaves — it records provenance
// only on the classification evidence map), it stamps source=port-banner-v1 and a
// below-cut numeric confidence. The value itself is never touched, so a miss never
// nulls a good value (D-11) and the wire never carries a product/version without
// its paired source + confidence (FPRINT-03). A service already carrying a wire
// source (a promoted recog-v1 match), or one with no product/version at all, is
// left untouched. The stamped identity is evidence only (D-15).
func backfillPhase4Provenance(s *payload.ServiceItem) {
	if s == nil || (s.Product == nil && s.ServiceVersion == nil) || s.ServiceIdentitySource != nil {
		return
	}
	source := sourcePortBannerV1
	confidence := confidencePortBannerV1
	s.ServiceIdentitySource = &source
	s.ServiceIdentityConfidence = &confidence
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
