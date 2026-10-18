package capabilities

import "testing"

// TestDetectReturnsValue proves Detect() runs without panic and returns a value
// struct (the three probes are best-effort and never fatal).
func TestDetectReturnsValue(t *testing.T) {
	t.Parallel()
	_ = Detect() // must not panic regardless of runtime permissions
}

// TestImmutableByValue proves ENG-06 immutability: a copy of a Capabilities
// value shares no mutable state with the original, so passing it by value to a
// stage can never alter the detected truth.
func TestImmutableByValue(t *testing.T) {
	t.Parallel()
	orig := Capabilities{UnprivilegedICMP: true, SystemPing: true, ARPCache: true}
	cp := orig
	cp.UnprivilegedICMP = false
	cp.SystemPing = false
	cp.ARPCache = false

	if !orig.UnprivilegedICMP || !orig.SystemPing || !orig.ARPCache {
		t.Fatalf("mutating a copy altered the original %+v — Capabilities is not immutable by value", orig)
	}
}
