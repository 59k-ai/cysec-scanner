// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Curated default scan set (PORT-01, D-01/D-02).
//
// DefaultPortSet is the conservative, high-signal set of TCP ports probed when
// the operator passes no --ports override. It is deliberately small: the ports
// that identify the services a mid-market LAN actually runs (remote access, file
// shares, directory, databases, web, mail, printing, management planes), chosen
// so a single polite pass yields strong classification evidence without scanning
// the whole 65k range. The classification rules key off these well-known ports,
// so an operator override widens coverage but no longer matches every rule.

// DefaultPortSet is the 37-port default scan set, in ascending order.
var DefaultPortSet = []int{
	21, 22, 23, 25, 53, 80, 88, 135, 139, 143,
	161, 389, 443, 445, 465, 554, 587, 631, 636, 993,
	995, 1433, 2049, 3268, 3306, 3389, 5432, 5900, 5985, 5986,
	7000, 8008, 8080, 8443, 9000, 9100, 27017,
}

// serviceNameByPort maps each well-known port to its human-spoken protocol name,
// used to label the ServiceName field of an emitted service. Ports absent from
// the map simply carry an empty service name.
var serviceNameByPort = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	88: "kerberos", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 554: "rtsp",
	587: "smtp-submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
	1433: "mssql", 2049: "nfs", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp",
	5432: "postgresql", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
	7000: "rtsp-alt", 8008: "http-alt", 8080: "http-proxy", 8443: "https-alt",
	9000: "cslistener", 9100: "jetdirect", 27017: "mongodb",
}

// minPort and maxPort bound a valid TCP port number.
const (
	minPort = 1
	maxPort = 65535
)

// ParsePorts parses an operator --ports override (D-02) into an ascending,
// de-duplicated port list. The spec is a comma-separated list of single ports
// and inclusive lo-hi ranges, e.g. "22,80,443,8000-8010". Every token must be
// numeric and within 1..65535, and a range must not be inverted; any violation
// returns a descriptive error rather than silently dropping the token. An empty
// or whitespace-only spec returns an error — the caller falls back to
// DefaultPortSet when no flag is given, so reaching here with nothing to parse is
// an operator mistake worth surfacing.
func ParsePorts(spec string) ([]int, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	seen := map[int]bool{}
	for _, raw := range strings.Split(trimmed, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			return nil, fmt.Errorf("empty port token in %q", spec)
		}
		if lo, hi, isRange := strings.Cut(token, "-"); isRange {
			loN, err := parsePort(strings.TrimSpace(lo))
			if err != nil {
				return nil, fmt.Errorf("invalid range %q: %w", token, err)
			}
			hiN, err := parsePort(strings.TrimSpace(hi))
			if err != nil {
				return nil, fmt.Errorf("invalid range %q: %w", token, err)
			}
			if loN > hiN {
				return nil, fmt.Errorf("inverted range %q: %d > %d", token, loN, hiN)
			}
			for p := loN; p <= hiN; p++ {
				seen[p] = true
			}
			continue
		}
		p, err := parsePort(token)
		if err != nil {
			return nil, err
		}
		seen[p] = true
	}

	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// parsePort parses a single numeric port token and enforces the 1..65535 band.
func parsePort(token string) (int, error) {
	n, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number", token)
	}
	if n < minPort || n > maxPort {
		return 0, fmt.Errorf("port %d out of range %d..%d", n, minPort, maxPort)
	}
	return n, nil
}
