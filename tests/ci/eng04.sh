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

# Every listener constructor form: inbound TCP/UDP/IP/unix/packet/multicast/
# HTTP sockets, the HTTP server forms that open their own listener (the
# ListenAndServe(TLS) method on any server value, an http.Server literal),
# the crypto/tls listener forms (tls.Listen, tls.NewListener), the test
# servers that bind loopback themselves (httptest.NewServer and friends,
# nettest.NewLocalListener; they can be imported from non-test code),
# the raw listen(2) and bind(2) wrappers (syscall, x/sys/unix,
# x/sys/windows; a bound datagram socket receives without listen), the
# named-pipe and Hyper-V socket listeners (go-winio ListenPipe and
# ListenHvsock, the raw Win32 CreateNamedPipe call) and the public
# ipc.Listen constructor. The `\(` on net.Listen, ipc.Listen and the raw
# wrappers keeps the net.Listener type from matching.
ENG04_PATTERN='net\.Listen\(|net\.ListenTCP|net\.ListenUDP|net\.ListenIP|net\.ListenPacket|net\.ListenUnix|net\.ListenMulticastUDP|net\.FileListener|net\.ListenConfig|icmp\.ListenPacket|http\.ListenAndServe|\.ListenAndServe(TLS)?\(|http\.Server\{|new\(http\.Server\)|http\.Serve\(|tls\.Listen\(|tls\.NewListener|httptest\.New(Unstarted|TLS)?Server|nettest\.NewLocalListener|syscall\.Listen\(|unix\.Listen\(|windows\.Listen\(|(syscall|unix|windows)\.Bind\(|ListenPipe|ListenHvsock|CreateNamedPipe|ipc\.Listen\('

# A grep cannot follow an aliased or dot import, so any non-blank alias of a
# package that has a listener constructor fails the gate outright: such a
# file would call the constructor under a name the pattern above never sees.
ENG04_ALIAS_PATTERN='^[^:]+:[0-9]+:[[:space:]]*(import[[:space:]]+)?([A-Za-z][A-Za-z0-9_]*|_[A-Za-z0-9_]+|\.)[[:space:]]+"(net|net/http|net/http/httptest|crypto/tls|golang\.org/x/net/nettest|syscall|golang\.org/x/sys/unix|golang\.org/x/sys/windows|golang\.org/x/net/icmp|github\.com/Microsoft/go-winio|github\.com/59k-ai/cysec-scanner/ipc)"'

# The pinned sites, one file+construct pair each. Every entry is anchored at
# the start of the path:line:content hit, so a file whose path merely ends in
# a pinned path, or a line that quotes a pinned site in a comment, is not
# exempt. Each entry admits exactly one hit, and that hit's line may carry
# no other listener construct, so a pinned file cannot hide a second call.
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
	'^internal/capabilities/capabilities\.go:[0-9]+:.*icmp\.ListenPacket'
	'^internal/netutil/mdns\.go:[0-9]+:.*net\.ListenUDP'
	'^ipc/listen_unix\.go:[0-9]+:.*net\.ListenUnix\("unix"'
	'^ipc/listen_windows\.go:[0-9]+:.*winio\.ListenPipe'
	'^tools/ipc-refhost/main\.go:[0-9]+:.*ipc\.Listen\('
)

ENG04_IPC_PKG='github.com/59k-ai/cysec-scanner/ipc'
ENG04_WINIO_MOD='github.com/Microsoft/go-winio'

_eng04_files() {
	local root=$1 files
	files=$(cd "$root" && git ls-files '*.go' -- ':!*_test.go' ':!tests/consumer') || return 2
	[ -n "$files" ] || { echo "ENG-04: no Go sources found under $root; scan would be vacuous" >&2; return 2; }
	printf '%s\n' "$files"
}

_eng04_hits() {
	local root=$1 files
	files=$(_eng04_files "$root") || return 2
	(cd "$root" && printf '%s\n' "$files" | xargs grep -HnE "$ENG04_PATTERN" 2>/dev/null) || true
}

# _eng04_constructs <hit>: how many listener constructs the content part of
# one path:line:content hit carries.
_eng04_constructs() {
	local content=${1#*:}
	content=${content#*:}
	grep -oE "$ENG04_PATTERN" <<<"$content" | wc -l | tr -d ' '
}

# eng04_scan <root>: no listener constructor outside the pinned sites, each
# pinned site exactly once, and no aliased import that could hide one.
eng04_scan() {
	local root=$1 files hits hit i matched bad="" aliases
	files=$(_eng04_files "$root") || return 1
	hits=$(_eng04_hits "$root") || return 1
	local -a seen=()
	for i in "${!ENG04_ALLOWLIST[@]}"; do seen[i]=0; done
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		matched=-1
		for i in "${!ENG04_ALLOWLIST[@]}"; do
			if [[ $hit =~ ${ENG04_ALLOWLIST[i]} ]]; then
				matched=$i
				break
			fi
		done
		if [ "$matched" -ge 0 ] && [ "${seen[matched]}" -eq 0 ] && [ "$(_eng04_constructs "$hit")" -eq 1 ]; then
			seen[matched]=1
			continue
		fi
		bad+="$hit"$'\n'
	done <<<"$hits"
	if [ -n "$bad" ]; then
		echo "ENG-04: listener constructor outside the pinned-site allowlist (or a pinned site hit twice):"
		printf '%s' "$bad"
		return 1
	fi
	aliases=$(cd "$root" && printf '%s\n' "$files" | xargs grep -HnE '^[[:space:]]*(import[[:space:]]+)?[A-Za-z_.][A-Za-z0-9_]*[[:space:]]+"' 2>/dev/null |
		grep -E "$ENG04_ALIAS_PATTERN" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*import[[:space:]]+"' || true)
	if [ -n "$aliases" ]; then
		echo "ENG-04: aliased import of a package with a listener constructor (the gate cannot follow it):"
		printf '%s\n' "$aliases"
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
