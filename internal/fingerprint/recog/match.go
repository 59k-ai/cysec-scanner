// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package recog

import (
	"regexp"
	"strings"
)

// maxParamBytes caps the length of any value extracted from an untrusted banner
// before it reaches a payload field. A banner is attacker-controlled input, so a
// capture group could carry an arbitrarily long or crafted value; capping (after
// control-char stripping) bounds what flows into product / version / cpe.
const maxParamBytes = 256

// Identity is the structured result of a successful match. All string fields are
// already sanitized (control-char stripped, length-capped). Confidence is the
// database's match confidence in [0,1]. Empty string fields mean the matched
// fingerprint did not supply that value.
type Identity struct {
	Product        string
	ServiceVersion string
	CPE            string
	// OSFamily / OSCPE carry an operating-system cue when the matched fingerprint
	// declares os.* params. They are evidence for a later OS-guess stage; this
	// package only surfaces them.
	OSFamily string
	OSCPE    string
	// Confidence is the database match confidence (its preference), in [0,1].
	Confidence float64
}

// cpeVarRe matches an interpolation token like {service.version} inside a CPE
// template value.
var cpeVarRe = regexp.MustCompile(`\{([a-z0-9_.]+)\}`)

// Match returns the identity of the FIRST fingerprint whose compiled pattern
// matches banner (declaration order — stable first-match-wins), and true. It
// returns the zero Identity and false when no fingerprint matches, when banner
// is empty, or when the database is empty. Match never raises: RE2 matching is
// linear-time and bounded, and every extracted value is sanitized and capped.
func (db *DB) Match(banner string) (Identity, bool) {
	if db == nil || banner == "" {
		return Identity{}, false
	}
	for _, c := range db.compiled {
		m := c.re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		vals := extractParams(c.params, m)
		return Identity{
			Product:        vals["service.product"],
			ServiceVersion: vals["service.version"],
			CPE:            vals["service.cpe23"],
			OSFamily:       firstNonEmpty(vals["os.family"], vals["os.product"]),
			OSCPE:          vals["os.cpe23"],
			Confidence:     db.preference,
		}, true
	}
	return Identity{}, false
}

// extractParams fills the param name->value map from a fingerprint's param table
// against a submatch slice: a param with a static value is used verbatim, an
// empty-value param takes capture group Pos. Values are sanitized and capped,
// then any value carrying a {name} token is interpolated against the other
// params (e.g. a CPE template referencing {service.version}).
func extractParams(params []xmlParam, m []string) map[string]string {
	vals := make(map[string]string, len(params))
	for _, p := range params {
		if p.Name == "" {
			continue
		}
		var raw string
		if p.Value != "" {
			raw = p.Value
		} else if p.Pos > 0 && p.Pos < len(m) {
			raw = m[p.Pos]
		} else {
			continue
		}
		vals[p.Name] = sanitizeParam(raw)
	}
	// Second pass: interpolate template tokens now that every param is captured.
	for name, v := range vals {
		if strings.IndexByte(v, '{') >= 0 {
			vals[name] = sanitizeParam(interpolate(v, vals))
		}
	}
	return vals
}

// interpolate replaces each {name} token in v with the corresponding param
// value, leaving an unresolved token untouched.
func interpolate(v string, vals map[string]string) string {
	return cpeVarRe.ReplaceAllStringFunc(v, func(tok string) string {
		name := tok[1 : len(tok)-1]
		if rep, ok := vals[name]; ok {
			return rep
		}
		return tok
	})
}

// sanitizeParam strips control characters from an untrusted value and caps its
// length (ASVS V5). It keeps only printable bytes so a hostile banner cannot
// smuggle terminal escapes or oversized blobs into a payload field.
func sanitizeParam(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
		if b.Len() >= maxParamBytes {
			break
		}
	}
	return b.String()
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
