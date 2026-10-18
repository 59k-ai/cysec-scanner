// Package governance enforces the cysec-scanner data-governance contract: the
// allowlist (single source of truth for every embedded data file, verified
// two-way by SHA-256) and the layered denylist (refuses contaminating
// copyleft/OEM datasets). Both gates run as Go tests and via cmd/datacheck in
// CI; neither participates in any compliance decision.
package governance

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
)

// allowlistPath is the manifest location inside the embedded data FS. It is
// skipped by the integrity walk (the manifest describes the data, it is not
// itself an allowlisted dataset).
const allowlistPath = "data/allowlist.json"

// isGovernanceDoc reports whether an embedded path is a human-readable
// governance/legal document rather than a dataset. The allowlist is the source
// of truth for DATASETS (their SHA-256 pin, license, provenance); a Markdown
// sign-off or README that happens to live under data/ (e.g. data/oui/SIGNOFF.md,
// the LIC-04 redistribution sign-off) is documentation, not a dataset, and must
// not be pinned — its content legitimately changes when a human records a
// sign-off, which would otherwise force a coupled allowlist hash edit. These
// docs are still content-scanned by the layered denylist (cmd/datacheck), so
// excluding them from the pin walk opens no contamination hole.
func isGovernanceDoc(p string) bool {
	return strings.HasSuffix(p, ".md")
}

// Entry is one record in data/allowlist.json. Every embeddable data file has
// exactly one Entry recording its integrity pin (SHA256), license, and
// provenance. Parsing is strict (see LoadAllowlist): an unknown field in the
// manifest is an error, mirroring the Collector's strict unknown-fields-forbidden schema.
type Entry struct {
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	License          string `json:"license"`
	LicenseNote      string `json:"license_note,omitempty"`
	Copyright        string `json:"copyright,omitempty"`
	ProvenanceURL    string `json:"provenance_url"`
	UpstreamSnapshot string `json:"upstream_snapshot,omitempty"`
	FetchDate        string `json:"fetch_date,omitempty"`

	// RegistryBlock and PrefixBits describe an IEEE OUI registry assignment and
	// are set only for the OUI datasets (D-08): the MAC-prefix is variable
	// length — MA-L is a 24-bit prefix, MA-M 28-bit, MA-S 36-bit. Recording the
	// prefix length here (rather than assuming a fixed 24-bit OUI) lets the
	// Phase-3 lookup do a longest-prefix match across all three blocks. Empty
	// for non-OUI datasets (Recog etc.).
	RegistryBlock string `json:"registry_block,omitempty"`
	PrefixBits    int    `json:"prefix_bits,omitempty"`
}

// manifest is the on-disk shape of data/allowlist.json.
type manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Entries       []Entry `json:"entries"`
}

// LoadAllowlist reads and strictly parses data/allowlist.json from fsys and
// returns the entries keyed by their declared path. Callers pass the embedded
// FS (scannerdata.DataFS) so the manifest and the data it describes come from
// the same compile-time snapshot.
//
// Strictness is deliberate: an unknown top-level or entry key, or a duplicate
// path, is a hard error. A typo must fail loudly in CI rather than silently
// drop a governance record.
func LoadAllowlist(fsys fs.FS) (map[string]Entry, error) {
	f, err := fsys.Open(allowlistPath)
	if err != nil {
		return nil, fmt.Errorf("open allowlist %q: %w", allowlistPath, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var m manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse allowlist %q: %w", allowlistPath, err)
	}
	// Reject trailing garbage after the single JSON document.
	if dec.More() {
		return nil, fmt.Errorf("parse allowlist %q: unexpected trailing data", allowlistPath)
	}
	if m.SchemaVersion != 1 {
		return nil, fmt.Errorf("allowlist %q: unsupported schema_version %d", allowlistPath, m.SchemaVersion)
	}

	out := make(map[string]Entry, len(m.Entries))
	for i, e := range m.Entries {
		if e.Path == "" {
			return nil, fmt.Errorf("allowlist entry %d: empty path", i)
		}
		if e.SHA256 == "" {
			return nil, fmt.Errorf("allowlist entry %q: empty sha256", e.Path)
		}
		if _, dup := out[e.Path]; dup {
			return nil, fmt.Errorf("allowlist entry %q: duplicate path", e.Path)
		}
		out[e.Path] = e
	}
	return out, nil
}

// VerifyEmbeddedData walks the embedded data tree and asserts a TWO-WAY match
// against the allowlist: every embedded file must appear in the manifest with a
// matching SHA-256, AND every manifest entry must have a present embedded file.
// The allowlist manifest itself is skipped. A mismatch in either direction is
// an error — this is the LIC-03 build-refusal gate.
func VerifyEmbeddedData(fsys fs.FS) error {
	manifest, err := LoadAllowlist(fsys)
	if err != nil {
		return err
	}

	seen := make(map[string]bool, len(manifest))

	walkErr := fs.WalkDir(fsys, "data", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || p == allowlistPath || isGovernanceDoc(p) {
			return nil
		}
		got, err := hashFile(fsys, p)
		if err != nil {
			return err
		}
		entry, ok := manifest[p]
		if !ok {
			return fmt.Errorf("embedded data file not on allowlist: %s", p)
		}
		if entry.SHA256 != got {
			return fmt.Errorf("hash drift for %s: manifest %s, embedded %s", p, entry.SHA256, got)
		}
		seen[p] = true
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	// Reverse direction: a manifest entry with no embedded file is a broken
	// pin (e.g. a file removed but left in the allowlist). Report
	// deterministically (sorted) so the failure message is stable.
	var missing []string
	for p := range manifest {
		if !seen[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("allowlisted file(s) missing from embedded data: %v", missing)
	}
	return nil
}

func hashFile(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", p, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %q: %w", p, err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
