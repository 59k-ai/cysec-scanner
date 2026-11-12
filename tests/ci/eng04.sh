#!/usr/bin/env bash
# Shared logic for the ENG-04 listener gate and the engine import-graph gate.
# The ci-gates workflow and tests/ci/ipc_gates_test.sh both call these
# functions, so CI and the local negative controls run one implementation.
#
# Each function takes the repository root as its only argument, prints a
# marker on success and returns non-zero on failure.
#
# CI usage:   bash tests/ci/eng04.sh <function> <repo-root>
# Test usage: . tests/ci/eng04.sh; eng04_scan "$root"

# Every listener constructor form: inbound TCP/UDP/unix/packet/multicast/HTTP
# sockets, the named-pipe listeners (go-winio ListenPipe, the raw Win32
# CreateNamedPipe call) and the public ipc.Listen constructor. The `\(` on
# net.Listen and ipc.Listen keeps the net.Listener type from matching.
ENG04_PATTERN='net\.Listen\(|net\.ListenTCP|net\.ListenUDP|net\.ListenPacket|net\.ListenUnix|net\.ListenMulticastUDP|net\.FileListener|net\.ListenConfig|icmp\.ListenPacket|http\.ListenAndServe|http\.Serve\(|ListenPipe|CreateNamedPipe|ipc\.Listen\('

# The pinned sites, one file+construct pair each:
#   - icmp.ListenPacket in internal/capabilities/capabilities.go: the
#     unprivileged ICMP capability probe, opened then closed, never a server.
#   - net.ListenUDP in internal/netutil/mdns.go: the mDNS reverse-query client
#     datagram on an ephemeral port, never a listening service.
#   - net.ListenUnix in ipc/listen_unix.go and winio.ListenPipe in
#     ipc/listen_windows.go: the local IPC endpoint, a filesystem socket or a
#     named pipe with an explicit ACL, for a separate host binary. No TCP, UDP
#     or HTTP form exists in the ipc package, and the engine never links it
#     (ipc_import_graph below).
#   - ipc.Listen( in tools/ipc-refhost/main.go: the reference host used by the
#     client tests, the only caller of the public constructor in this repo.
ENG04_ALLOWLIST=(
	'internal/capabilities/capabilities\.go:[0-9]+:.*icmp\.ListenPacket'
	'internal/netutil/mdns\.go:[0-9]+:.*net\.ListenUDP'
	'ipc/listen_unix\.go:[0-9]+:.*net\.ListenUnix\("unix"'
	'ipc/listen_windows\.go:[0-9]+:.*winio\.ListenPipe'
	'tools/ipc-refhost/main\.go:[0-9]+:.*ipc\.Listen\('
)

ENG04_IPC_PKG='github.com/59k-ai/cysec-scanner/ipc'
ENG04_WINIO_MOD='github.com/Microsoft/go-winio'

_eng04_hits() {
	local root=$1 files
	files=$(cd "$root" && git ls-files '*.go' -- ':!*_test.go' ':!tests/consumer') || return 2
	[ -n "$files" ] || { echo "ENG-04: no Go sources found under $root; scan would be vacuous" >&2; return 2; }
	(cd "$root" && printf '%s\n' "$files" | xargs grep -nE "$ENG04_PATTERN" 2>/dev/null) || true
}

# eng04_scan <root>: no listener constructor outside the pinned sites.
eng04_scan() {
	local root=$1 hits filtered allow
	hits=$(_eng04_hits "$root") || return 1
	allow=$(IFS='|'; printf '%s' "${ENG04_ALLOWLIST[*]}")
	filtered=$(printf '%s\n' "$hits" | grep -vE "$allow" | grep -vE '^$' || true)
	if [ -n "$filtered" ]; then
		echo "ENG-04: listener constructor outside the pinned-site allowlist:"
		printf '%s\n' "$filtered"
		return 1
	fi
	echo "NO_INBOUND_SOCKET"
}

# eng04_targets_exist <root>: every pinned site is still present, so the
# allowlist cannot silently go stale and exempt a future file of the same name.
eng04_targets_exist() {
	local root=$1 hits site rc=0
	hits=$(_eng04_hits "$root") || return 1
	for site in "${ENG04_ALLOWLIST[@]}"; do
		if ! printf '%s\n' "$hits" | grep -qE "$site"; then
			echo "ENG-04: pinned listener site vanished: $site"
			rc=1
		fi
	done
	[ "$rc" -eq 0 ] || return 1
	echo "ALLOWLIST_TARGETS_EXIST"
}

# ipc_import_graph <root>: the engine (cmd/cysec-scanner and scanner/...)
# never links the ipc package or go-winio, on any shipped OS.
ipc_import_graph() {
	local root=$1 os deps rc=0
	for os in linux darwin windows; do
		if ! deps=$(cd "$root" && GOOS=$os go list -deps ./cmd/cysec-scanner ./scanner/... 2>&1); then
			echo "import-graph: go list failed for GOOS=$os:"
			printf '%s\n' "$deps"
			rc=1
			continue
		fi
		if printf '%s\n' "$deps" | grep -qxE "$ENG04_IPC_PKG(/.*)?"; then
			echo "import-graph: the engine links $ENG04_IPC_PKG on GOOS=$os"
			rc=1
		fi
		if printf '%s\n' "$deps" | grep -qE "^$ENG04_WINIO_MOD(/|$)"; then
			echo "import-graph: the engine links $ENG04_WINIO_MOD on GOOS=$os"
			rc=1
		fi
	done
	[ "$rc" -eq 0 ] || return 1
	echo "IPC_IMPORT_GRAPH_CLEAN"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	set -u
	case "${1:-}" in
	eng04_scan | eng04_targets_exist | ipc_import_graph)
		[ -n "${2:-}" ] || { echo "usage: $0 <function> <repo-root>" >&2; exit 2; }
		"$1" "$2"
		;;
	*)
		echo "usage: $0 {eng04_scan|eng04_targets_exist|ipc_import_graph} <repo-root>" >&2
		exit 2
		;;
	esac
fi
