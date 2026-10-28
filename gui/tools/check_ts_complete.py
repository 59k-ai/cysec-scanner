#!/usr/bin/env python3
# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Translation completeness gate (I18N-01, threat T-13-66).
#
# Usage: check_ts_complete.py FILE.ts [FILE.ts ...]
#
# Fails (exit 1) when any message in any given Qt Linguist .ts file is
# unfinished, vanished, obsolete or missing its <translation>, has an empty
# translation, has an empty plural form, or uses a different placeholder set
# (%1..%9, %L1..%L9, %n) than its source. The placeholder check runs per
# plural form, so every form must carry %n when the source does. Prints one
# "path: reason: source" line per offence, or the TS_COMPLETE sentinel when
# every file is clean.
#
# Stdlib only and Qt-version independent on purpose: Qt 6.8 lrelease has no
# -fail-on-unfinished and lcheck only exists from 6.11, while CI builds the
# 6.8 floor too. The script takes arbitrary .ts paths so the second GUI
# (Phase 14) reuses it unchanged.

import re
import sys
import xml.etree.ElementTree as ET

PLACEHOLDER = re.compile(r"%(?:n|L?[1-9])")
BAD_TYPES = ("unfinished", "vanished", "obsolete")


def placeholders(text):
    # %L1 and %1 refer to the same argument; compare the argument set.
    return sorted({p.replace("L", "") for p in PLACEHOLDER.findall(text)})


def check_file(path):
    problems = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        return [f"{path}: unreadable: {exc}"]

    for msg in root.iter("message"):
        source = msg.findtext("source", default="")
        tr = msg.find("translation")
        if tr is None:
            problems.append(f"{path}: missing translation: {source!r}")
            continue

        kind = tr.get("type") or ""
        if kind in BAD_TYPES:
            problems.append(f"{path}: {kind}: {source!r}")
            continue

        forms = [f.text or "" for f in tr.iter("numerusform")]
        if msg.get("numerus") == "yes" and not forms:
            problems.append(f"{path}: plural message without numerusforms: {source!r}")
            continue
        if forms:
            if any(not f.strip() for f in forms):
                problems.append(f"{path}: empty numerusform: {source!r}")
                continue
            candidates = forms
        else:
            text = tr.text or ""
            if not text.strip():
                problems.append(f"{path}: empty translation: {source!r}")
                continue
            candidates = [text]

        expected = placeholders(source)
        for candidate in candidates:
            if placeholders(candidate) != expected:
                problems.append(
                    f"{path}: placeholder mismatch: {source!r} -> {candidate!r}"
                )
    return problems


def main(argv):
    if not argv:
        print("usage: check_ts_complete.py FILE.ts [FILE.ts ...]", file=sys.stderr)
        return 2
    problems = []
    for path in argv:
        problems.extend(check_file(path))
    if problems:
        print("\n".join(problems))
        print(f"{len(problems)} translation problem(s) found", file=sys.stderr)
        return 1
    print("TS_COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
