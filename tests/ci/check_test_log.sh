#!/usr/bin/env bash
# check_test_log.sh <go-test-v-log> <test-name>...
#
# Fails unless every named test (or subtest, as Parent/child) has a
# `--- PASS: <name> (` line in a `go test -v` log, and fails on any
# `--- SKIP` line at all. A hard-gated job must not turn green because a test
# skipped or never ran: the require-env variables turn missing preconditions
# into failures, and this check catches a test that was renamed, filtered out
# by -run, or skipped through some other path.
#
# The caller checks the go test exit status first; this script only reads the
# log, so no pipe can mask that status.
set -u

log=${1:-}
[ -n "$log" ] && [ -f "$log" ] || { echo "usage: $0 <go-test-v-log> <test-name>..." >&2; exit 2; }
shift
[ "$#" -gt 0 ] || { echo "no sentinel test names given; the check would be vacuous" >&2; exit 2; }

rc=0
for name in "$@"; do
	if grep -qF -- "--- PASS: $name (" "$log"; then
		echo "SENTINEL_PASS $name"
	else
		echo "missing PASS sentinel: $name"
		rc=1
	fi
done

if grep -nF -- "--- SKIP" "$log"; then
	echo "skipped tests found in a hard-gated IPC run (lines above)"
	rc=1
fi

[ "$rc" -eq 0 ] || exit 1
echo "IPC_SENTINELS_OK"
