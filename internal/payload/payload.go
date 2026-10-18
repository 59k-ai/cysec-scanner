// Package payload is the Go-side hand-mirror of the cysec.watch Collector wire
// schema at v5.
//
// The Collector's strict reference schema is the single SOURCE OF TRUTH; these
// structs reproduce its field names, JSON tags and enum string values exactly
// so a marshalled Payload re-validates under that strict (unknown-fields-
// forbidden) schema. Agreement between the two is confirmed out-of-tree by a
// round-trip validation against the reference schema.
//
// Two serialization invariants are load-bearing (D-03 / PAY-04):
//   - Required slices are initialised to the empty literal ([]T{}, never a nil
//     slice) so they marshal to JSON "[]" and not "null"; the strict model
//     rejects null for a list field.
//   - The five additive v5 scalar fields are pointer types (*string) so an unset
//     value marshals to JSON null, letting Phase-3 discovery tell "not observed"
//     (null) from a real empty value. A set pointer marshals to its value.
package payload

// SchemaVersion is the wire-schema version this mirror targets. It MUST equal
// the Collector's PAYLOAD_SCHEMA_VERSION (5); the cloud accepts only v5.
const SchemaVersion = 5

// Payload is the top-level Collector -> cloud envelope.
type Payload struct {
	SchemaVersion       int                      `json:"schema_version"`
	PayloadType         string                   `json:"payload_type"`
	CollectorVersion    string                   `json:"collector_version"`
	Assets              []AssetItem              `json:"assets"`
	Identities          []IdentityItem           `json:"identities"`
	ServiceExposures    []ServiceExposureItem    `json:"service_exposures"`
	Vulnerabilities     []VulnerabilityItem      `json:"vulnerabilities"`
	ConfigurationChecks []ConfigurationCheckItem `json:"configuration_checks"`
	PasswordPolicies    []PasswordPolicyItem     `json:"password_policies"`
	SoftwareInventory   []SoftwareInventoryItem  `json:"software_inventory"`
	MissingKbs          []MissingKbItem          `json:"missing_kbs"`
	TLSProbes           []TLSProbeItem           `json:"tls_probes"`
	// PayloadIDHash is nil until the Collector runner stamps the canonical-JSON
	// SHA-256; nil marshals to JSON null (payload.py: Optional[str] = None).
	PayloadIDHash *string `json:"payload_id_hash"`
}

// ServiceItem is a network service nested under AssetItem.services
// (payload.py:ServiceItem).
type ServiceItem struct {
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"`
	ServiceName   string `json:"service_name"`
	ExposureLevel string `json:"exposure_level"`
	TLSVersion    string `json:"tls_version"`
	// v5 (PAY-03, D-02/D-03) — structured service identity, nullable.
	ServiceVersion *string `json:"service_version"`
	Product        *string `json:"product"`
	CPE            *string `json:"cpe"`
}

// NetworkAliasItem is a secondary (hostname, address) pair for the same
// physical host (payload.py:NetworkAliasItem).
type NetworkAliasItem struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
}

// ClassificationEvidence is the per-asset classification verdict
// (payload.py:ClassificationEvidence). Carried as a pointer on AssetItem so an
// unset verdict marshals to JSON null (Optional in the model).
type ClassificationEvidence struct {
	AssetType     string            `json:"asset_type"`
	Confidence    float64           `json:"confidence"`
	RuleName      string            `json:"rule_name"`
	Evidence      map[string]string `json:"evidence"`
	SecurityFlags []string          `json:"security_flags"`
}

// AssetItem is one discovered/inventoried host (payload.py:AssetItem).
type AssetItem struct {
	ExternalID        string                  `json:"external_id"`
	Hostname          string                  `json:"hostname"`
	FQDN              string                  `json:"fqdn"`
	IPAddress         *string                 `json:"ip_address"`
	OperatingSystem   string                  `json:"operating_system"`
	OSFingerprintHint string                  `json:"os_fingerprint_hint"`
	AssetType         string                  `json:"asset_type"`
	Managed           bool                    `json:"managed"`
	InternetFacing    bool                    `json:"internet_facing"`
	Services          []ServiceItem           `json:"services"`
	Classification    *ClassificationEvidence `json:"classification_evidence"`
	NetworkAliases    []NetworkAliasItem      `json:"network_aliases"`
	// v5 (PAY-02, D-03) — L2 discovery evidence, nullable.
	MACAddress *string `json:"mac_address"`
	MACVendor  *string `json:"mac_vendor"`
}

// IdentityItem is one identity record (payload.py:IdentityItem).
type IdentityItem struct {
	ExternalID   string  `json:"external_id"`
	Username     string  `json:"username"`
	DisplayName  string  `json:"display_name"`
	Email        string  `json:"email"`
	Department   string  `json:"department"`
	Source       string  `json:"source"`
	IsActive     bool    `json:"is_active"`
	IsPrivileged bool    `json:"is_privileged"`
	MFAEnabled   bool    `json:"mfa_enabled"`
	MFAMethod    string  `json:"mfa_method"`
	LastLoginAt  *string `json:"last_login_at"`
}

// ServiceExposureItem is a top-level flattened service exposure
// (payload.py:ServiceExposureItem). It carries the same three v5 structured
// service fields as ServiceItem (D-02 — both representations have full fidelity).
type ServiceExposureItem struct {
	AssetExternalID string `json:"asset_external_id"`
	AssetID         string `json:"asset_id"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	ServiceName     string `json:"service_name"`
	ExposureLevel   string `json:"exposure_level"`
	TLSVersion      string `json:"tls_version"`
	// v5 (PAY-03, D-02/D-03) — nullable.
	ServiceVersion *string `json:"service_version"`
	Product        *string `json:"product"`
	CPE            *string `json:"cpe"`
}

// VulnerabilityItem is one CVE finding (payload.py:VulnerabilityItem).
type VulnerabilityItem struct {
	AssetExternalID string   `json:"asset_external_id"`
	AssetID         string   `json:"asset_id"`
	CVEID           string   `json:"cve_id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	CVSSScore       *float64 `json:"cvss_score"`
	FixAvailable    bool     `json:"fix_available"`
	PatchDueAt      *string  `json:"patch_due_at"`
	ServicePort     *int     `json:"service_port"`
	ServiceProtocol string   `json:"service_protocol"`
}

// ConfigurationCheckItem is one configuration check result
// (payload.py:ConfigurationCheckItem).
type ConfigurationCheckItem struct {
	AssetExternalID string  `json:"asset_external_id"`
	AssetID         string  `json:"asset_id"`
	CheckCode       string  `json:"check_code"`
	Title           string  `json:"title"`
	Status          string  `json:"status"`
	Description     string  `json:"description"`
	Severity        string  `json:"severity"`
	ExpectedValue   string  `json:"expected_value"`
	ObservedValue   string  `json:"observed_value"`
	ServicePort     *int    `json:"service_port"`
	ServiceProtocol string  `json:"service_protocol"`
}

// PasswordPolicyItem is a default-domain or PSO password policy
// (payload.py:PasswordPolicyItem).
type PasswordPolicyItem struct {
	PolicyName         string   `json:"policy_name"`
	Scope              string   `json:"scope"`
	MinLength          *int     `json:"min_length"`
	HistoryLength      *int     `json:"history_length"`
	MaxAgeDays         *int     `json:"max_age_days"`
	MinAgeDays         *int     `json:"min_age_days"`
	LockoutThreshold   *int     `json:"lockout_threshold"`
	LockoutDurationMin *int     `json:"lockout_duration_minutes"`
	ComplexityRequired *bool    `json:"complexity_required"`
	AppliesTo          []string `json:"applies_to"`
	EvidenceDN         string   `json:"evidence_dn"`
}

// SoftwareInventoryItem is a per-host installed-software entry
// (payload.py:SoftwareInventoryItem).
type SoftwareInventoryItem struct {
	AssetExternalID string            `json:"asset_external_id"`
	DisplayName     string            `json:"display_name"`
	DisplayVersion  *string           `json:"display_version"`
	Publisher       *string           `json:"publisher"`
	InstallDate     *string           `json:"install_date"`
	InstallSource   string            `json:"install_source"`
	SourceEvidence  map[string]string `json:"source_evidence"`
}

// MissingKbItem is a missing-KB row (payload.py:MissingKbItem).
type MissingKbItem struct {
	AssetExternalID string  `json:"asset_external_id"`
	KBID            string  `json:"kb_id"`
	CVE             string  `json:"cve"`
	Title           string  `json:"title"`
	Severity        string  `json:"severity"`
	ReleasedDate    *string `json:"released_date"`
}

// TLSVersionResult is one row of the per-version TLS acceptance matrix
// (payload.py:TlsVersionResult).
type TLSVersionResult struct {
	Version          string `json:"version"`
	Accepted         bool   `json:"accepted"`
	NegotiatedCipher string `json:"negotiated_cipher"`
	WeakCipher       bool   `json:"weak_cipher"`
	Error            string `json:"error"`
}

// TLSProbeItem is an internal-host TLS posture probe result. ProbedAt is an
// RFC3339 timestamp string the reference schema's datetime field parses.
type TLSProbeItem struct {
	AssetExternalID string             `json:"asset_external_id"`
	Host            string             `json:"host"`
	Port            int                `json:"port"`
	Results         []TLSVersionResult `json:"results"`
	ProbedAt        string             `json:"probed_at"`
}

// NewEmpty returns an empty-ish but strict-valid v5 payload: schema_version 5,
// the given payload_type, every required slice initialised to its empty literal
// (so each marshals to "[]" not "null"), and a nil payload_id_hash (JSON null —
// the Collector runner stamps it). This is what the Phase-2 engine emits before
// any real scanning logic lands (D-04).
func NewEmpty(payloadType, collectorVersion string) Payload {
	return Payload{
		SchemaVersion:       SchemaVersion,
		PayloadType:         payloadType,
		CollectorVersion:    collectorVersion,
		Assets:              []AssetItem{},
		Identities:          []IdentityItem{},
		ServiceExposures:    []ServiceExposureItem{},
		Vulnerabilities:     []VulnerabilityItem{},
		ConfigurationChecks: []ConfigurationCheckItem{},
		PasswordPolicies:    []PasswordPolicyItem{},
		SoftwareInventory:   []SoftwareInventoryItem{},
		MissingKbs:          []MissingKbItem{},
		TLSProbes:           []TLSProbeItem{},
		PayloadIDHash:       nil,
	}
}

// Normalize forces every REQUIRED container — top-level and nested — to a
// non-nil value so it marshals to the empty literal ("[]" / "{}") rather than
// JSON "null" (WR-02). NewEmpty handles the top-level lists, but a populated
// asset built from scratch in a later scanning stage (Phase 3+) can carry nil
// nested slices/maps: AssetItem.Services / AssetItem.NetworkAliases,
// ClassificationEvidence.Evidence / ClassificationEvidence.SecurityFlags,
// PasswordPolicyItem.AppliesTo, SoftwareInventoryItem.SourceEvidence and
// TLSProbeItem.Results all mirror a required, default-empty field in the
// reference schema — the strict (unknown-fields-forbidden) schema 400-rejects a
// null for any of them, which would silently drop a populated asset's evidence.
// Call this immediately before marshalling the wire payload.
func (p *Payload) Normalize() {
	// Top-level required lists (belt-and-braces: a Phase-3 stage may replace
	// a whole slice with a nil one).
	if p.Assets == nil {
		p.Assets = []AssetItem{}
	}
	if p.Identities == nil {
		p.Identities = []IdentityItem{}
	}
	if p.ServiceExposures == nil {
		p.ServiceExposures = []ServiceExposureItem{}
	}
	if p.Vulnerabilities == nil {
		p.Vulnerabilities = []VulnerabilityItem{}
	}
	if p.ConfigurationChecks == nil {
		p.ConfigurationChecks = []ConfigurationCheckItem{}
	}
	if p.PasswordPolicies == nil {
		p.PasswordPolicies = []PasswordPolicyItem{}
	}
	if p.SoftwareInventory == nil {
		p.SoftwareInventory = []SoftwareInventoryItem{}
	}
	if p.MissingKbs == nil {
		p.MissingKbs = []MissingKbItem{}
	}
	if p.TLSProbes == nil {
		p.TLSProbes = []TLSProbeItem{}
	}

	// Nested required containers.
	for i := range p.Assets {
		a := &p.Assets[i]
		if a.Services == nil {
			a.Services = []ServiceItem{}
		}
		if a.NetworkAliases == nil {
			a.NetworkAliases = []NetworkAliasItem{}
		}
		if a.Classification != nil {
			if a.Classification.Evidence == nil {
				a.Classification.Evidence = map[string]string{}
			}
			if a.Classification.SecurityFlags == nil {
				a.Classification.SecurityFlags = []string{}
			}
		}
	}
	for i := range p.PasswordPolicies {
		if p.PasswordPolicies[i].AppliesTo == nil {
			p.PasswordPolicies[i].AppliesTo = []string{}
		}
	}
	for i := range p.SoftwareInventory {
		if p.SoftwareInventory[i].SourceEvidence == nil {
			p.SoftwareInventory[i].SourceEvidence = map[string]string{}
		}
	}
	for i := range p.TLSProbes {
		if p.TLSProbes[i].Results == nil {
			p.TLSProbes[i].Results = []TLSVersionResult{}
		}
	}
}
