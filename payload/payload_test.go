// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

// TestEmptyPayloadSerialization pins the null-vs-[] invariant (PAY-04): every
// required slice on an empty-ish payload marshals to "[]", never "null", and
// schema_version marshals as SchemaVersion under its exact tag. A nil required slice (the
// regression this guards) would marshal to "null" and fail the strict model.
func TestEmptyPayloadSerialization(t *testing.T) {
	t.Parallel()

	got, err := json.Marshal(NewEmpty("full", "cysec-scanner-engine/0.0.0"))
	if err != nil {
		t.Fatalf("marshal empty payload: %v", err)
	}
	s := string(got)

	// Every required slice must be [] not null.
	for _, tag := range []string{
		"assets", "identities", "service_exposures", "vulnerabilities",
		"configuration_checks", "password_policies", "software_inventory",
		"missing_kbs", "tls_probes",
	} {
		wantEmpty := `"` + tag + `":[]`
		wantNull := `"` + tag + `":null`
		if strings.Contains(s, wantNull) {
			t.Errorf("required slice %q serialized to null, want []", tag)
		}
		if !strings.Contains(s, wantEmpty) {
			t.Errorf("required slice %q not serialized as []; json=%s", tag, s)
		}
	}

	// schema_version tracks the SchemaVersion constant under its exact tag.
	if want := fmt.Sprintf(`"schema_version":%d`, SchemaVersion); !strings.Contains(s, want) {
		t.Errorf("schema_version not %d under schema_version tag; json=%s", SchemaVersion, s)
	}
	// scan_status is null when unset (v7: a complete scan).
	if !strings.Contains(s, `"scan_status":null`) {
		t.Errorf("scan_status should be null when unset; json=%s", s)
	}
	// scan_metadata is null when unset (nil pointer).
	if !strings.Contains(s, `"scan_metadata":null`) {
		t.Errorf("scan_metadata should be null when unset; json=%s", s)
	}
	// payload_id_hash is null (unset pointer).
	if !strings.Contains(s, `"payload_id_hash":null`) {
		t.Errorf("payload_id_hash should be null when unset; json=%s", s)
	}
	// payload_type carries the value verbatim.
	if !strings.Contains(s, `"payload_type":"full"`) {
		t.Errorf("payload_type missing/wrong; json=%s", s)
	}
}

// TestNilSliceWouldSerializeNull documents WHY NewEmpty initialises slices to
// the empty literal: a zero-value Payload (nil slices) marshals its required
// lists to null, which the strict reference schema rejects. This is the exact
// failure the [] invariant prevents.
func TestNilSliceWouldSerializeNull(t *testing.T) {
	t.Parallel()
	got, err := json.Marshal(Payload{SchemaVersion: SchemaVersion, PayloadType: "full"})
	if err != nil {
		t.Fatalf("marshal zero payload: %v", err)
	}
	if !strings.Contains(string(got), `"assets":null`) {
		t.Fatalf("expected a nil required slice to marshal to null (proving the hazard); json=%s", string(got))
	}
}

// TestV5PointerFieldsNullVsValue pins the pointer-Optional invariant (PAY-02/
// PAY-03/PAY-04): the five v5 scalar fields marshal to null when nil and to the
// exact value when set, on asset, nested service, and ServiceExposureItem.
func TestV5PointerFieldsNullVsValue(t *testing.T) {
	t.Parallel()

	t.Run("unset marshals to null", func(t *testing.T) {
		t.Parallel()
		asset, _ := json.Marshal(AssetItem{})
		for _, tag := range []string{"mac_address", "mac_vendor"} {
			if !strings.Contains(string(asset), `"`+tag+`":null`) {
				t.Errorf("unset asset.%s not null; json=%s", tag, string(asset))
			}
		}
		svc, _ := json.Marshal(ServiceItem{})
		exp, _ := json.Marshal(ServiceExposureItem{})
		for _, tag := range []string{"service_version", "product", "cpe"} {
			if !strings.Contains(string(svc), `"`+tag+`":null`) {
				t.Errorf("unset service.%s not null; json=%s", tag, string(svc))
			}
			if !strings.Contains(string(exp), `"`+tag+`":null`) {
				t.Errorf("unset service_exposure.%s not null; json=%s", tag, string(exp))
			}
		}
	})

	t.Run("set marshals to value", func(t *testing.T) {
		t.Parallel()
		asset, _ := json.Marshal(AssetItem{MACAddress: ptr("00:11:22:33:44:55"), MACVendor: ptr("Dell Inc.")})
		if !strings.Contains(string(asset), `"mac_address":"00:11:22:33:44:55"`) ||
			!strings.Contains(string(asset), `"mac_vendor":"Dell Inc."`) {
			t.Errorf("set asset MAC fields not value-faithful; json=%s", string(asset))
		}
		svc, _ := json.Marshal(ServiceItem{ServiceVersion: ptr("9.0p1"), Product: ptr("OpenSSH"), CPE: ptr("cpe:/a:openbsd:openssh:9.0p1")})
		if !strings.Contains(string(svc), `"service_version":"9.0p1"`) ||
			!strings.Contains(string(svc), `"product":"OpenSSH"`) ||
			!strings.Contains(string(svc), `"cpe":"cpe:/a:openbsd:openssh:9.0p1"`) {
			t.Errorf("set service fields not value-faithful; json=%s", string(svc))
		}
	})
}

// TestPopulatedRoundTrip proves PAY-02 + PAY-03 survive a marshal/unmarshal
// cycle unchanged: a populated asset (MAC set) carrying a populated nested
// service, plus a populated ServiceExposureItem, all round-trip value-faithful
// across BOTH service representations (D-02).
func TestPopulatedRoundTrip(t *testing.T) {
	t.Parallel()

	in := NewEmpty("full", "cysec-scanner-engine/0.0.0")
	in.Assets = []AssetItem{{
		ExternalID:      "ws01",
		Hostname:        "WS01",
		IPAddress:       ptr("10.77.0.20"),
		OperatingSystem: "Windows Server 2025",
		AssetType:       "server",
		Managed:         true,
		MACAddress:      ptr("aa:bb:cc:dd:ee:ff"),
		MACVendor:       ptr("VMware, Inc."),
		Services: []ServiceItem{{
			Port:           22,
			Protocol:       "tcp",
			ServiceName:    "ssh",
			ExposureLevel:  "internal",
			ServiceVersion: ptr("9.6p1"),
			Product:        ptr("OpenSSH"),
			CPE:            ptr("cpe:/a:openbsd:openssh:9.6p1"),
		}},
	}}
	in.ServiceExposures = []ServiceExposureItem{{
		AssetExternalID: "ws01",
		Port:            443,
		Protocol:        "tcp",
		ServiceName:     "https",
		ExposureLevel:   "internet",
		ServiceVersion:  ptr("1.25.3"),
		Product:         ptr("nginx"),
		CPE:             ptr("cpe:/a:nginx:nginx:1.25.3"),
	}}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Payload
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.Assets) != 1 || len(out.Assets[0].Services) != 1 {
		t.Fatalf("shape lost in round-trip: %+v", out)
	}
	a := out.Assets[0]
	if got := deref(a.MACAddress); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac_address round-trip = %q", got)
	}
	if got := deref(a.MACVendor); got != "VMware, Inc." {
		t.Errorf("mac_vendor round-trip = %q", got)
	}
	svc := a.Services[0]
	if deref(svc.ServiceVersion) != "9.6p1" || deref(svc.Product) != "OpenSSH" || deref(svc.CPE) != "cpe:/a:openbsd:openssh:9.6p1" {
		t.Errorf("nested service v5 fields not round-trip faithful: %+v", svc)
	}
	exp := out.ServiceExposures[0]
	if deref(exp.ServiceVersion) != "1.25.3" || deref(exp.Product) != "nginx" || deref(exp.CPE) != "cpe:/a:nginx:nginx:1.25.3" {
		t.Errorf("service_exposure v5 fields not round-trip faithful: %+v", exp)
	}
	if out.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version round-trip = %d, want %d", out.SchemaVersion, SchemaVersion)
	}
}

// TestNormalizePopulatedAssetNestedSlicesNotNull is the WR-02 proof: a
// POPULATED asset whose nested required containers are left nil (the latent
// Phase-3 data-loss hazard) marshals every one of them to the empty literal
// ("[]" / "{}"), never "null", AFTER Normalize(). The strict reference schema
// 400-rejects a null for any required, default-empty list/dict field, so
// a null here would silently drop a populated asset at ingest.
func TestNormalizePopulatedAssetNestedSlicesNotNull(t *testing.T) {
	t.Parallel()

	pl := NewEmpty("full", "cysec-scanner-engine/0.0.0")
	pl.Assets = []AssetItem{{
		ExternalID: "ws01",
		Hostname:   "WS01",
		IPAddress:  ptr("10.77.0.20"),
		MACAddress: ptr("aa:bb:cc:dd:ee:ff"),
		Classification: &ClassificationEvidence{
			AssetType:  "server",
			Confidence: 0.9,
			RuleName:   "open_ports.smb_rdp",
			// Evidence + SecurityFlags left nil on purpose — the hazard.
		},
		// Services + NetworkAliases left nil on purpose — the hazard.
	}}
	pl.PasswordPolicies = []PasswordPolicyItem{{
		PolicyName: "default",
		Scope:      "domain",
		EvidenceDN: "DC=example,DC=local",
		// AppliesTo left nil on purpose.
	}}
	pl.SoftwareInventory = []SoftwareInventoryItem{{
		AssetExternalID: "ws01",
		DisplayName:     "OpenSSL",
		InstallSource:   "registry_64",
		// SourceEvidence left nil on purpose.
	}}
	pl.TLSProbes = []TLSProbeItem{{
		AssetExternalID: "tls:ws01:443",
		Host:            "ws01",
		Port:            443,
		ProbedAt:        "2026-01-01T00:00:00Z",
		// Results left nil on purpose.
	}}

	pl.Normalize()
	got, err := json.Marshal(pl)
	if err != nil {
		t.Fatalf("marshal populated payload: %v", err)
	}
	s := string(got)

	// Every required nested container must serialize to its empty literal.
	for _, want := range []string{
		`"services":[]`,
		`"network_aliases":[]`,
		`"evidence":{}`,
		`"security_flags":[]`,
		`"applies_to":[]`,
		`"source_evidence":{}`,
		`"results":[]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("required nested container not serialized as empty literal %q; json=%s", want, s)
		}
	}

	// And none of them may serialize to null (the strict-model 400 trap).
	for _, bad := range []string{
		`"services":null`,
		`"network_aliases":null`,
		`"evidence":null`,
		`"security_flags":null`,
		`"applies_to":null`,
		`"source_evidence":null`,
		`"results":null`,
	} {
		if strings.Contains(s, bad) {
			t.Errorf("required nested container serialized to null %q; json=%s", bad, s)
		}
	}
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// TestStrictValidV6 is the scanner-side half of the cross-repo v6 contract: a
// payload with the v6 fingerprint-provenance fields SET serializes them
// value-faithfully, and one with them UNSET serializes each to null (value +
// source + confidence null TOGETHER — the prefer-unknown encoding), while every
// required slice still serializes to [] and the whole body round-trips. The
// scanner emits the SAME field names the Collector's strict reference schema
// declared, so a scanner-emitted v6 body validates under that unknown-fields-
// forbidden model (Pitfall 1 guard).
func TestStrictValidV6(t *testing.T) {
	t.Parallel()

	t.Run("unset v6 fields serialize null together", func(t *testing.T) {
		t.Parallel()
		svc, _ := json.Marshal(ServiceItem{})
		exp, _ := json.Marshal(ServiceExposureItem{})
		for _, tag := range []string{"service_identity_source", "service_identity_confidence"} {
			if !strings.Contains(string(svc), `"`+tag+`":null`) {
				t.Errorf("unset service.%s not null; json=%s", tag, string(svc))
			}
			if !strings.Contains(string(exp), `"`+tag+`":null`) {
				t.Errorf("unset service_exposure.%s not null; json=%s", tag, string(exp))
			}
		}
		asset, _ := json.Marshal(AssetItem{})
		for _, tag := range []string{"os_guess", "os_guess_source", "os_guess_confidence"} {
			if !strings.Contains(string(asset), `"`+tag+`":null`) {
				t.Errorf("unset asset.%s not null; json=%s", tag, string(asset))
			}
		}
		pl, _ := json.Marshal(NewEmpty("full", "engine/test"))
		if !strings.Contains(string(pl), `"scan_metadata":null`) {
			t.Errorf("unset scan_metadata not null; json=%s", string(pl))
		}
	})

	t.Run("set v6 fields serialize value-faithfully and round-trip", func(t *testing.T) {
		t.Parallel()
		in := NewEmpty("full", "engine/test")
		in.ScanMetadata = &ScanMetadata{RecogDBVersion: ptr("cf937c0"), OSSignatureDBVersion: ptr("osfp-v1")}
		in.Assets = []AssetItem{{
			ExternalID:        "ip:10.0.0.5",
			OSGuess:           ptr("Linux"),
			OSGuessSource:     ptr("osfp-ttl-v1"),
			OSGuessConfidence: ptr(0.6),
			Services: []ServiceItem{{
				Port:                      22,
				Product:                   ptr("OpenSSH"),
				ServiceVersion:            ptr("9.6p1"),
				CPE:                       ptr("cpe:/a:openbsd:openssh:9.6p1"),
				ServiceIdentitySource:     ptr("recog-v1"),
				ServiceIdentityConfidence: ptr(0.9),
			}},
		}}
		in.ServiceExposures = []ServiceExposureItem{{
			AssetExternalID:           "ip:10.0.0.5",
			Port:                      22,
			ServiceIdentitySource:     ptr("recog-v1"),
			ServiceIdentityConfidence: ptr(0.9),
		}}
		in.Normalize()

		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s := string(raw)
		for _, want := range []string{
			fmt.Sprintf(`"schema_version":%d`, SchemaVersion),
			`"recog_db_version":"cf937c0"`,
			`"os_signature_db_version":"osfp-v1"`,
			`"os_guess":"Linux"`,
			`"os_guess_source":"osfp-ttl-v1"`,
			`"os_guess_confidence":0.6`,
			`"service_identity_source":"recog-v1"`,
			`"service_identity_confidence":0.9`,
			`"assets":[`,
			`"service_exposures":[`,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q; json=%s", want, s)
			}
		}

		var out Payload
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out.ScanMetadata == nil || deref(out.ScanMetadata.RecogDBVersion) != "cf937c0" {
			t.Errorf("scan_metadata lost in round-trip: %+v", out.ScanMetadata)
		}
		if len(out.Assets) != 1 || out.Assets[0].OSGuessConfidence == nil || *out.Assets[0].OSGuessConfidence != 0.6 {
			t.Errorf("os_guess_confidence lost in round-trip: %+v", out.Assets)
		}
		svc := out.Assets[0].Services[0]
		if svc.ServiceIdentityConfidence == nil || *svc.ServiceIdentityConfidence != 0.9 {
			t.Errorf("service_identity_confidence lost in round-trip: %+v", svc)
		}
	})
}

// TestSchemaVersionIsV8 is the single deliberate literal lock on the wire
// version. Every other test tracks the SchemaVersion constant.
func TestSchemaVersionIsV8(t *testing.T) {
	if SchemaVersion != 8 {
		t.Fatalf("SchemaVersion = %d, want 8", SchemaVersion)
	}
	if ScanStatusCancelled != "cancelled" {
		t.Fatalf("ScanStatusCancelled = %q, want \"cancelled\"", ScanStatusCancelled)
	}
}

// TestV7ScanStatusNullVsValue pins the v7 scan_status pointer boundary: nil
// marshals to JSON null (complete scan), a set pointer to "cancelled", and
// both survive an unmarshal round-trip.
func TestV7ScanStatusNullVsValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *string
		want   string
	}{
		{"null", nil, `"scan_status":null`},
		{"cancelled", ptr(ScanStatusCancelled), `"scan_status":"cancelled"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := NewEmpty("full", "engine/0.0.0")
			in.ScanStatus = tc.status
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(raw), tc.want) {
				t.Fatalf("missing %s; json=%s", tc.want, raw)
			}
			var out Payload
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			switch {
			case tc.status == nil && out.ScanStatus != nil:
				t.Fatalf("scan_status round-trip = %q, want nil", *out.ScanStatus)
			case tc.status != nil && (out.ScanStatus == nil || *out.ScanStatus != *tc.status):
				t.Fatalf("scan_status round-trip = %v, want %q", out.ScanStatus, *tc.status)
			}
		})
	}
}

// TestV8AssetFieldsNullWhenUnset pins that the three v8 asset fields are
// emitted as JSON null when unset. Dropping the key instead (omitempty) would
// make "no evidence" look like a pre-v8 body.
func TestV8AssetFieldsNullWhenUnset(t *testing.T) {
	raw, err := json.Marshal(AssetItem{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `"os_build":null,"ubr":null,"installed_kbs":null`; !strings.Contains(string(raw), want) {
		t.Fatalf("missing %s; json=%s", want, raw)
	}
}

// TestV8AssetFieldsSetValues pins the wire form of the set fields, including a
// UBR of zero, which is a real value and must not read as unset.
func TestV8AssetFieldsSetValues(t *testing.T) {
	raw, err := json.Marshal(AssetItem{
		OSBuild:      ptr("10.0.20348"),
		UBR:          ptr(int64(0)),
		InstalledKbs: &InstalledKbs{Status: InstalledKbsCollected, Kbs: []string{"KB5066782"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `"os_build":"10.0.20348","ubr":0,"installed_kbs":{"status":"collected","kbs":["KB5066782"]}`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("missing %s; json=%s", want, raw)
	}
}

// TestV8InstalledKbsStatusValues locks the literal status strings, which are
// part of the wire contract.
func TestV8InstalledKbsStatusValues(t *testing.T) {
	for got, want := range map[string]string{
		InstalledKbsCollected:    "collected",
		InstalledKbsUnavailable:  "unavailable",
		InstalledKbsNotAttempted: "not_attempted",
	} {
		if got != want {
			t.Errorf("status constant = %q, want %q", got, want)
		}
	}
}

// TestV8NormalizeKbsNotNull proves Normalize turns a nil kbs slice into [] on
// every asset that has the object, keeps collected ids, and leaves an absent
// object null: null means "no evidence", which is not the same as an empty
// collected inventory.
func TestV8NormalizeKbsNotNull(t *testing.T) {
	p := NewEmpty("full", "engine/0.0.0")
	p.Assets = []AssetItem{
		{ExternalID: "a", InstalledKbs: &InstalledKbs{Status: InstalledKbsUnavailable}},
		{ExternalID: "b", InstalledKbs: &InstalledKbs{Status: InstalledKbsNotAttempted}},
		{ExternalID: "c", InstalledKbs: &InstalledKbs{Status: InstalledKbsCollected, Kbs: []string{"KB890830"}}},
		{ExternalID: "d"},
	}
	p.Normalize()

	for i, want := range []string{
		`"installed_kbs":{"status":"unavailable","kbs":[]}`,
		`"installed_kbs":{"status":"not_attempted","kbs":[]}`,
		`"installed_kbs":{"status":"collected","kbs":["KB890830"]}`,
		`"installed_kbs":null`,
	} {
		raw, err := json.Marshal(p.Assets[i])
		if err != nil {
			t.Fatalf("marshal asset %d: %v", i, err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("asset %d: missing %s; json=%s", i, want, raw)
		}
	}
}

// contractDir holds a byte-identical copy of the frozen v8 contract fixtures.
const contractDir = "testdata/contract_v8"

// strictDecode decodes with unknown fields rejected, as a strict consumer does.
func strictDecode(raw []byte) (Payload, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Payload
	err := dec.Decode(&p)
	return p, err
}

// TestV8ContractManifest proves the copied fixtures have not drifted. The manifest
// itself is pinned, each listed file is checked, and only the two files this
// repository deliberately does not carry may be absent: the schema names a private
// host in its $id, and the canonical vectors need an encoder this library does not
// have, because stamping the payload hash is the consumer's job.
func TestV8ContractManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(contractDir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	const wantManifest = "8b46c12daf1f2af84e6622a2cb0edaeae71e66c73c654ea5ea7544e0ef6a60b4"
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != wantManifest {
		t.Fatalf("manifest sha256 = %s, want %s", got, wantManifest)
	}
	omitted := map[string]bool{"payload.schema.json": true, "canonical/vectors.json": true}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed manifest line %q", line)
		}
		want, name := fields[0], fields[1]
		body, err := os.ReadFile(filepath.Join(contractDir, filepath.FromSlash(name)))
		if omitted[name] {
			if err == nil {
				t.Errorf("%s is present, want it left out", name)
			}
			continue
		}
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(body)); got != want {
			t.Errorf("%s sha256 = %s, want %s", name, got, want)
		}
		checked++
	}
	if checked != 6 {
		t.Errorf("checked %d fixtures, want 6", checked)
	}
}

// TestV8FixturesStrictRoundTrip decodes the contract fixtures with unknown
// fields rejected, re-marshals them, and compares the trees, so a field the
// mirror drops or renames fails here. The comparison is on decoded JSON because
// the fixtures are key-sorted and the Go encoder writes struct order.
func TestV8FixturesStrictRoundTrip(t *testing.T) {
	for _, name := range []string{"v8_full.json", "v8_statuses.json", "v8_legacy.json", "v8_diacritics.json"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(contractDir, "fixtures", name))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			p, err := strictDecode(raw)
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if p.SchemaVersion != SchemaVersion {
				t.Errorf("schema_version = %d, want %d", p.SchemaVersion, SchemaVersion)
			}
			out, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var want, got any
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("decode fixture tree: %v", err)
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("decode output tree: %v", err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("round-trip changed the document\n--- fixture ---\n%s\n--- output ---\n%s", raw, out)
			}
		})
	}
}

// TestV7ShapedBodyStillDecodes proves a body without the v8 keys is accepted, and
// that the keys come back null: every v8 field is nullable.
func TestV7ShapedBodyStillDecodes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(contractDir, "fixtures", "v7_shaped.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p, err := strictDecode(raw)
	if err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if p.SchemaVersion != 7 {
		t.Errorf("schema_version = %d, want 7", p.SchemaVersion)
	}
	for i, a := range p.Assets {
		if a.OSBuild != nil || a.UBR != nil || a.InstalledKbs != nil {
			t.Errorf("asset %d has v8 fields set: %+v", i, a)
		}
	}
}

// TestV8RejectCasesAtTheDecoder runs the contract's invalid bodies through the
// strict decoder. Three are shape errors it must refuse. The other five are value
// rules (status enum, KB id and build patterns, kbs only when collected, ubr range)
// that a type mirror cannot express: they decode here on purpose, and a consumer
// that sends payloads has to validate them.
func TestV8RejectCasesAtTheDecoder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(contractDir, "fixtures", "reject_cases.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var cases []struct {
		Name string          `json:"name"`
		Body json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode cases: %v", err)
	}
	wantRefused := map[string]bool{
		"asset_unknown_key":         true,
		"installed_kbs_unknown_key": true,
		"ubr_float":                 true,
		"kb_lowercase":              false,
		"kbs_while_unavailable":     false,
		"os_build_bare_build":       false,
		"status_partial":            false,
		"ubr_negative":              false,
	}
	if len(cases) != len(wantRefused) {
		t.Fatalf("got %d cases, want %d", len(cases), len(wantRefused))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			want, known := wantRefused[c.Name]
			if !known {
				t.Fatalf("unexpected case %q", c.Name)
			}
			if _, err := strictDecode(c.Body); (err != nil) != want {
				t.Errorf("decode error = %v, want refused = %v", err, want)
			}
		})
	}
}
