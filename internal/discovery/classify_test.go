package discovery

import (
	"testing"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// TestClassifyEvidence proves the DISC-05 evidence assembly: a host whose
// internal record carries a known MAC vendor, the mDNS resolver-hit flag, and a
// reply TTL of 64 yields a non-nil classification_evidence whose evidence map
// collects a mac_vendor entry, an mdns entry, and an os family of "linux"; the
// asset_type is "unknown" on BOTH the asset and the classification (D-02); and
// security_flags is a non-nil empty slice. NetBIOS did not answer, so no netbios
// entry appears.
func TestClassifyEvidence(t *testing.T) {
	vendor := "Nokia Shanghai Bell"
	e := hostEntry{ip: "10.0.0.5", ttl: 64, macVendor: &vendor, mdnsHit: true}
	a := payload.AssetItem{}
	classifyAsset(&a, e)

	if a.Classification == nil {
		t.Fatal("classification_evidence is nil, want non-nil for every discovered asset")
	}
	c := a.Classification
	if c.Evidence == nil {
		t.Fatal("classification evidence map is nil, want non-nil")
	}
	if got := c.Evidence[evidenceKeyMACVendor]; got != vendor {
		t.Errorf("evidence[%q] = %q, want %q", evidenceKeyMACVendor, got, vendor)
	}
	if got := c.Evidence[evidenceKeyOSTTLFamily]; got != "linux" {
		t.Errorf("evidence[%q] = %q, want linux", evidenceKeyOSTTLFamily, got)
	}
	if got, ok := c.Evidence[evidenceKeyMDNS]; !ok || got != evidenceValuePresent {
		t.Errorf("evidence[%q] = %q (present=%v), want %q present", evidenceKeyMDNS, got, ok, evidenceValuePresent)
	}
	if _, ok := c.Evidence[evidenceKeyNetBIOS]; ok {
		t.Errorf("evidence[%q] present, want absent (NetBIOS did not answer)", evidenceKeyNetBIOS)
	}
	if a.AssetType != assetTypeUnknown {
		t.Errorf("AssetItem.asset_type = %q, want %q (D-02)", a.AssetType, assetTypeUnknown)
	}
	if c.AssetType != assetTypeUnknown {
		t.Errorf("classification asset_type = %q, want %q (D-02)", c.AssetType, assetTypeUnknown)
	}
	if c.SecurityFlags == nil {
		t.Error("security_flags is nil, want non-nil empty slice")
	}
	if len(c.SecurityFlags) != 0 {
		t.Errorf("security_flags = %v, want empty", c.SecurityFlags)
	}
	if a.OSFingerprintHint != "linux" {
		t.Errorf("os_fingerprint_hint = %q, want linux", a.OSFingerprintHint)
	}
	if a.Managed || a.InternetFacing {
		t.Errorf("managed=%v internet_facing=%v, want both false (cloud owns exposure truth)", a.Managed, a.InternetFacing)
	}
}

// TestClassifyMDNSFlagFalseNoEntry proves the CONSUMER←PRODUCER contract: the
// mdns/netbios evidence entry is driven by the 03-03 resolver-hit flag, never
// re-probed. A host whose mdns flag is false emits NO mdns entry (and no
// fabricated false one).
func TestClassifyMDNSFlagFalseNoEntry(t *testing.T) {
	e := hostEntry{ip: "10.0.0.6", ttl: 128, mdnsHit: false, netbiosHit: true}
	a := payload.AssetItem{}
	classifyAsset(&a, e)

	if _, ok := a.Classification.Evidence[evidenceKeyMDNS]; ok {
		t.Errorf("evidence[%q] present with mdnsHit=false, want absent (flag-driven, not fabricated)", evidenceKeyMDNS)
	}
	if got, ok := a.Classification.Evidence[evidenceKeyNetBIOS]; !ok || got != evidenceValuePresent {
		t.Errorf("evidence[%q] = %q (present=%v), want %q present (netbiosHit=true)", evidenceKeyNetBIOS, got, ok, evidenceValuePresent)
	}
	if got := a.Classification.Evidence[evidenceKeyOSTTLFamily]; got != "windows" {
		t.Errorf("evidence[%q] = %q, want windows (TTL 128)", evidenceKeyOSTTLFamily, got)
	}
}

// TestTTLFamily proves the coarse TTL→OS-family mapping boundaries and that a
// garbage/absent TTL collapses to "" with no crash (Pitfall 7).
func TestTTLFamily(t *testing.T) {
	cases := []struct {
		ttl  int
		want string
	}{
		{0, ""},    // absent (zero value)
		{-1, ""},   // garbage
		{1, "linux"},
		{64, "linux"},
		{65, "windows"},
		{128, "windows"},
		{129, "network-device"},
		{255, "network-device"},
		{256, ""}, // garbage (above the IPv4 TTL ceiling)
		{1000, ""},
	}
	for _, tc := range cases {
		if got := ttlFamily(tc.ttl); got != tc.want {
			t.Errorf("ttlFamily(%d) = %q, want %q", tc.ttl, got, tc.want)
		}
	}
}

// TestClassifyPreservesRoutedL2Segment proves a routed host's pre-existing
// evidence["l2_segment"]="routed" survives the classification merge (merge, not
// overwrite), while the TTL-derived family is still added alongside it.
func TestClassifyPreservesRoutedL2Segment(t *testing.T) {
	a := payload.AssetItem{
		Classification: &payload.ClassificationEvidence{
			AssetType:     routedAssetType,
			Evidence:      map[string]string{evidenceKeyL2Segment: evidenceValueRouted},
			SecurityFlags: []string{},
		},
	}
	e := hostEntry{ip: "203.0.113.9", ttl: 54, routed: true}
	classifyAsset(&a, e)

	if got := a.Classification.Evidence[evidenceKeyL2Segment]; got != evidenceValueRouted {
		t.Errorf("evidence[%q] = %q after merge, want %q preserved", evidenceKeyL2Segment, got, evidenceValueRouted)
	}
	if got := a.Classification.Evidence[evidenceKeyOSTTLFamily]; got != "linux" {
		t.Errorf("evidence[%q] = %q, want linux (TTL 54) merged alongside l2_segment", evidenceKeyOSTTLFamily, got)
	}
	if a.AssetType != assetTypeUnknown {
		t.Errorf("routed asset_type = %q, want %q (D-02)", a.AssetType, assetTypeUnknown)
	}
}

// TestClassifyNoSignals proves a host with no vendor, a garbage TTL, and no
// resolver hits still gets a non-nil classification_evidence with asset_type
// "unknown", a non-nil (empty) evidence map, and an empty os_fingerprint_hint —
// never a crash or a null required container.
func TestClassifyNoSignals(t *testing.T) {
	e := hostEntry{ip: "10.0.0.9", ttl: 0}
	a := payload.AssetItem{}
	classifyAsset(&a, e)

	if a.Classification == nil || a.Classification.Evidence == nil || a.Classification.SecurityFlags == nil {
		t.Fatalf("classification/evidence/security_flags must be non-nil, got %+v", a.Classification)
	}
	if a.AssetType != assetTypeUnknown || a.Classification.AssetType != assetTypeUnknown {
		t.Errorf("asset_type must be %q on both asset and classification", assetTypeUnknown)
	}
	if a.OSFingerprintHint != "" {
		t.Errorf("os_fingerprint_hint = %q, want \"\" for a garbage/absent TTL", a.OSFingerprintHint)
	}
}
