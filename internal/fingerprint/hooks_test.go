// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"context"
	"sync"
	"testing"

	"github.com/59k-ai/cysec-scanner/internal/capabilities"
	"github.com/59k-ai/cysec-scanner/internal/scanstate"
	"github.com/59k-ai/cysec-scanner/payload"
)

// TestFingerprintReportsProgressPerAsset proves fingerprint progress ticks once
// per asset and reaches done == total == number of assets.
func TestFingerprintReportsProgressPerAsset(t *testing.T) {
	st := scanstate.New("full", "engine/test")
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		addr := ip
		st.AddAsset(payload.AssetItem{
			ExternalID:     "ip:" + ip,
			IPAddress:      &addr,
			Services:       []payload.ServiceItem{},
			NetworkAliases: []payload.NetworkAliasItem{},
		})
	}
	var mu sync.Mutex
	var calls [][2]int
	st.SetObserver(&scanstate.Observer{OnProgress: func(stage string, done, total int) {
		if stage != "fingerprint" {
			return
		}
		mu.Lock()
		calls = append(calls, [2]int{done, total})
		mu.Unlock()
	}})
	if err := Run(context.Background(), st, capabilities.Capabilities{}, Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("progress calls = %v, want 3", calls)
	}
	for i, c := range calls {
		if c[0] != i+1 || c[1] != 3 {
			t.Errorf("call %d = %v, want [%d 3]", i, c, i+1)
		}
	}
}
