#!/usr/bin/env bash
# Local negative controls for the listener gate and the engine import-graph
# gate. CI runs the same functions from tests/ci/eng04.sh, so this script
# proves the exact text CI runs: a clean tree passes, and each injected
# regression (a listener in the engine, a named-pipe listener outside the
# pinned sites, the engine linking the ipc package, a pinned site removed, a
# path that only ends in a pinned path, a pinned site quoted in a comment, a
# second call in a pinned file, a raw listen wrapper, an aliased import)
# reddens the gate.
#
# Usage: bash tests/ci/ipc_gates_test.sh   (from anywhere inside the repo)
set -u

ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel) || exit 1
# shellcheck source=tests/ci/eng04.sh
. "$ROOT/tests/ci/eng04.sh" || { echo "cannot load tests/ci/eng04.sh"; exit 1; }

export GOWORK=off
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ipc-gates.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT

FAILED=0

fail() {
	echo "FAIL: $*"
	FAILED=1
}

# copy_tree <name>: a fresh copy of the tracked tree (working-tree contents),
# returned on stdout. The caller edits it, then calls index_tree so that
# git ls-files in the copy sees the edit.
copy_tree() {
	local dst="$TMP/$1"
	mkdir -p "$dst"
	(cd "$ROOT" && git ls-files -z | xargs -0 tar -cf - 2>/dev/null) | (cd "$dst" && tar -xf -)
	printf '%s\n' "$dst"
}

index_tree() {
	(cd "$1" && git init -q . && git add -A) >/dev/null 2>&1
}

# expect_fail <label> <function> <tree>: the gate must exit non-zero.
expect_fail() {
	local label=$1 fn=$2 tree=$3 out
	if out=$("$fn" "$tree" 2>&1); then
		fail "negative control $label: $fn passed on a broken tree"
		printf '%s\n' "$out"
	else
		echo "NEGATIVE_CONTROL_OK $label ($fn)"
	fi
}

# Clean tree: all three gates pass and print their markers.
for fn in eng04_scan eng04_targets_exist ipc_import_graph; do
	if out=$("$fn" "$ROOT" 2>&1); then
		printf '%s\n' "$out"
	else
		fail "$fn failed on the clean tree"
		printf '%s\n' "$out"
	fi
done

# A: a local socket listener in the engine.
A=$(copy_tree a)
printf '\n// net.ListenUnix("unix", nil)\n' >> "$A/scanner/scanner.go"
index_tree "$A"
expect_fail A eng04_scan "$A"

# B: a named-pipe listener outside the pinned sites.
B=$(copy_tree b)
printf 'package discovery\n\n// winio.ListenPipe(`x`, nil)\n' > "$B/internal/discovery/zz_negative_control.go"
index_tree "$B"
expect_fail B eng04_scan "$B"

# C: the engine links the ipc package.
C=$(copy_tree c)
printf 'package scanner\n\nimport _ "github.com/59k-ai/cysec-scanner/ipc"\n' > "$C/scanner/zz_negative_control.go"
index_tree "$C"
expect_fail C ipc_import_graph "$C"

# D: a pinned listener site disappears, so the allowlist entry is stale.
D=$(copy_tree d)
rm -f "$D/ipc/listen_windows.go"
index_tree "$D"
expect_fail D eng04_targets_exist "$D"

# E: a file whose path ends in a pinned path is not the pinned file.
E=$(copy_tree e)
mkdir -p "$E/tools/x/ipc"
printf 'package ipc\n\n// net.ListenUnix("unix", nil)\n' > "$E/tools/x/ipc/listen_unix.go"
index_tree "$E"
expect_fail E eng04_scan "$E"

# F: a line that quotes a pinned site in a trailing comment is not exempt.
F=$(copy_tree f)
printf '\n// net.Listen("tcp", ":0") // ipc/listen_unix.go:1: net.ListenUnix("unix"\n' >> "$F/scanner/scanner.go"
index_tree "$F"
expect_fail F eng04_scan "$F"

# G: a pinned file carrying a second listener call.
G=$(copy_tree g)
printf '\n// net.ListenUnix("unix", nil)\n' >> "$G/ipc/listen_unix.go"
index_tree "$G"
expect_fail G eng04_scan "$G"

# H: a raw listen(2) wrapper.
H=$(copy_tree h)
printf '\n// syscall.Listen(fd, 1)\n' >> "$H/scanner/scanner.go"
index_tree "$H"
expect_fail H eng04_scan "$H"

# I: an aliased net import, under which a constructor call is invisible.
I=$(copy_tree i)
printf 'package discovery\n\nimport n "net"\n\nvar _ = n.IPv4len\n' > "$I/internal/discovery/zz_negative_control.go"
index_tree "$I"
expect_fail I eng04_scan "$I"

if [ "$FAILED" -ne 0 ]; then
	echo "IPC_GATES_TEST_FAILED"
	exit 1
fi
echo "IPC_GATES_TEST_OK"
