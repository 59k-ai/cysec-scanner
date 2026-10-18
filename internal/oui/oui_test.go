package oui

import "testing"

// TestLookupVendor pins the longest-prefix behaviour against the real embedded
// IEEE registry blocks. The Assignment values below are taken verbatim from the
// shipped CSVs so the test fails loudly if the data snapshot or the lookup logic
// drifts.
func TestLookupVendor(t *testing.T) {
	cases := []struct {
		name string
		mac  string
		want string // "" means a nil result is expected
	}{
		{
			// 8C1F64AFA is a 36-bit MA-S assignment (DATA ELECTRONIC DEVICES);
			// its 24-bit prefix 8C1F64 is the MA-L block holder (IEEE
			// Registration Authority). Longest-prefix MUST pick the MA-S owner.
			name: "MA-S beats MA-L (longest prefix wins)",
			mac:  "8C:1F:64:AF:A1:23",
			want: "DATA ELECTRONIC DEVICES, INC",
		},
		{
			// C85CE27 is a 28-bit MA-M assignment; its 24-bit prefix C85CE2 is
			// the MA-L registry holder, so the MA-M owner must win.
			name: "MA-M assignment resolves to the MA-M owner",
			mac:  "C8:5C:E2:71:23:45",
			want: "SYNERGY SYSTEMS AND SOLUTIONS",
		},
		{
			// 286FB9 is a plain 24-bit MA-L assignment with no MA-M/MA-S carve-out.
			name: "MA-L assignment resolves to the MA-L owner",
			mac:  "28:6F:B9:01:02:03",
			want: "Nokia Shanghai Bell Co., Ltd.",
		},
		{
			// 741AE09 is a redacted MA-M row (Organization Name "Private"). The
			// longest match is authoritative: a redacted assignment resolves to
			// nil rather than leaking the literal "Private" or falling through to
			// the parent MA-L registry holder.
			name: "Private redaction resolves to nil",
			mac:  "74:1A:E0:9A:BC:DE",
			want: "",
		},
		{
			name: "malformed MAC resolves to nil without panic",
			mac:  "not-a-mac",
			want: "",
		},
		{
			name: "empty string resolves to nil",
			mac:  "",
			want: "",
		},
		{
			name: "fewer than 6 hex digits resolves to nil",
			mac:  "8C:1F",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LookupVendor(tc.mac)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("LookupVendor(%q) = %q, want nil", tc.mac, *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("LookupVendor(%q) = nil, want %q", tc.mac, tc.want)
			}
			if *got != tc.want {
				t.Fatalf("LookupVendor(%q) = %q, want %q", tc.mac, *got, tc.want)
			}
		})
	}
}

// TestLookupVendorHyphenAndBareHex proves separator-insensitive normalization:
// hyphen-separated and bare-hex inputs resolve identically to the colon form.
func TestLookupVendorHyphenAndBareHex(t *testing.T) {
	forms := []string{"8C-1F-64-AF-A1-23", "8c1f64afa123", "8C1F64AFA123"}
	for _, f := range forms {
		got := LookupVendor(f)
		if got == nil || *got != "DATA ELECTRONIC DEVICES, INC" {
			t.Fatalf("LookupVendor(%q) = %v, want DATA ELECTRONIC DEVICES, INC", f, got)
		}
	}
}
