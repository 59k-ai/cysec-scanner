package scanstate

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cysec-watch/cysec-scanner/internal/payload"
)

// TestSnapshotIsolation proves Payload() returns a snapshot whose asset slice
// does not alias internal state: mutating the snapshot leaves the accumulator
// unchanged.
func TestSnapshotIsolation(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	ip := "10.0.0.1"
	st.AddAsset(payload.AssetItem{ExternalID: "ip:10.0.0.1", IPAddress: &ip})

	snap := st.Payload()
	if len(snap.Assets) != 1 {
		t.Fatalf("snapshot assets = %d, want 1", len(snap.Assets))
	}
	snap.Assets = append(snap.Assets, payload.AssetItem{ExternalID: "ip:10.0.0.2"})

	if again := st.Payload(); len(again.Assets) != 1 {
		t.Fatalf("mutating the snapshot leaked into the accumulator: assets = %d, want 1", len(again.Assets))
	}
}

// TestConcurrentAddAsset proves the accumulator is safe under concurrent writers
// (run with -race; mirrors the concurrent sweep, Pitfall 4).
func TestConcurrentAddAsset(t *testing.T) {
	t.Parallel()
	st := New("full", "engine/test")
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.0.%d", i)
			st.AddAsset(payload.AssetItem{ExternalID: "ip:" + ip, IPAddress: &ip})
		}(i)
	}
	wg.Wait()
	if got := len(st.Payload().Assets); got != n {
		t.Fatalf("concurrent AddAsset produced %d assets, want %d", got, n)
	}
}
