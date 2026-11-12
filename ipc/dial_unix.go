// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ipc

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// Dial connects to a local endpoint created by Listen. The address must be
// an absolute socket path; abstract names are refused for the same reason
// Listen refuses them.
func Dial(ctx context.Context, address string) (net.Conn, error) {
	if !filepath.IsAbs(address) || strings.HasPrefix(address, "@") || strings.IndexByte(address, 0) >= 0 {
		return nil, fmt.Errorf("%w: socket path must be absolute", ErrInvalidAddress)
	}
	return (&net.Dialer{}).DialContext(ctx, "unix", address)
}
