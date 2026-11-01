// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package capabilities

// sysctlARPReadable is darwin-only; elsewhere the ARP source is /proc/net/arp
// or the arp command.
func sysctlARPReadable() bool { return false }
