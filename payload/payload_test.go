// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package payload

import (
	"encoding/json"
	"fmt"
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

// TestSchemaVersionIsV7 is the single deliberate literal lock on the wire
// version (D-25). Every other test tracks the SchemaVersion constant.
func TestSchemaVersionIsV7(t *testing.T) {
	if SchemaVersion != 7 {
		t.Fatalf("SchemaVersion = %d, want 7", SchemaVersion)
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
