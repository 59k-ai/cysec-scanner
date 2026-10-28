#!/usr/bin/env python3
# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# SGUI-06 vocabulary gate and plain-text rendering gate (threats T-13-64,
# T-13-65).
#
# Usage: check_vocabulary.py ROOT [--plaintext]
#
# Vocabulary (always): the public scanner GUI is a local, standalone tool, so
# no user-visible string may talk about the concepts of a hosted product
# (connecting a device to a remote service, signing in, remote storage,
# grading). The gate applies an English and a German ban list,
# case-insensitive and on word boundaries ("Repair" does not match "pair"),
# to exactly the user-visible text:
#   - string literals passed to qsTr / qsTranslate / QT_TR_NOOP /
#     QT_TRANSLATE_NOOP in ROOT/**/*.qml, *.cpp and *.h (identifiers and
#     comments are not scanned, so a property called "tokenizer" is fine);
#   - <source>, <translation> and <numerusform> text in ROOT/**/*.ts;
#   - the whole text of ROOT/**/*.md.
# Build directories (any path component starting with "build") are skipped.
#
# Plain text (--plaintext): data shown by the GUI comes from the network and
# may carry markup, so in ROOT/src/**/*.qml
#   - Text/TextEdit RichText, StyledText, AutoText and MarkdownText are banned;
#   - every Text, Label, TextArea and TextEdit object must set
#     textFormat: Text.PlainText (or TextEdit.PlainText) on itself. PlainLabel
#     already does, so using PlainLabel needs nothing extra.
# The scan is a brace-depth walk over the source with comments and string
# literals blanked out; no QML parser is needed.
#
# Prints one "path:line: reason" line per offence, otherwise VOCABULARY_CLEAN
# (and PLAINTEXT_CLEAN when --plaintext ran). Stdlib only, so Phase 14 reuses
# it for the second GUI by pointing it at another ROOT.

import os
import re
import sys
import xml.etree.ElementTree as ET

# Single words take optional English inflections; multi-word terms match
# across any run of whitespace or hyphens.
EN_TERMS = [
    "pair", "pairing", "cloud", "tenant", "API key", "token", "login", "log in",
    "sign in", "account", "upload", "sync", "synchronise", "synchronize",
    "synchronisation", "synchronization", "dashboard", "licence key",
    "license key", "subscription", "NIS2", "compliance", "score", "verdict",
]
DE_TERMS = [
    "koppeln", "gekoppelt", "Kopplung", "Koppelung", "Cloud", "Mandant",
    "Mandanten", "API-Schlüssel", "Token", "Anmeldung", "anmelden",
    "angemeldet", "Konto", "Konten", "hochladen", "hochgeladen", "Upload",
    "synchronisieren", "synchronisiert", "Synchronisierung", "Synchronisation",
    "Dashboard", "Lizenzschlüssel", "Abonnement", "NIS2", "Compliance",
    "Bewertung", "Punktzahl", "Urteil",
]
EN_SUFFIX = r"(?:s|es|d|ed|ing)?"

PLAIN_FORMAT = re.compile(r"\btextFormat\s*:\s*(?:Text|TextEdit)\.PlainText\b")
NON_PLAIN_FORMAT = re.compile(
    r"\b(?:Text|TextEdit)\.(?:RichText|StyledText|AutoText|MarkdownText)\b"
)
TEXT_OBJECT = re.compile(r"(?<![\w])(Text|Label|TextArea|TextEdit)\s*\{")
TR_CALL = re.compile(r"\b(?:qsTr|qsTranslate|QT_TR_NOOP|QT_TRANSLATE_NOOP)\s*\(")
SOURCE_EXTS = (".qml", ".cpp", ".h")


def _term_pattern(term, english):
    parts = [re.escape(p) for p in re.split(r"[\s-]+", term)]
    body = r"[\s-]+".join(parts)
    if english and len(parts) == 1:
        body += EN_SUFFIX
    return r"\b" + body + r"\b"


BANNED = re.compile(
    "|".join(
        [_term_pattern(t, True) for t in EN_TERMS]
        + [_term_pattern(t, False) for t in DE_TERMS]
    ),
    re.IGNORECASE,
)


def walk(root, exts, under=None):
    base = os.path.join(root, under) if under else root
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(
            d for d in dirnames if not d.startswith("build") and not d.startswith(".")
        )
        for name in sorted(filenames):
            if name.endswith(exts):
                yield os.path.join(dirpath, name)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def blank_code(src):
    """Return src with comments and string-literal contents replaced by spaces.

    Lengths and newlines are kept, so offsets and line numbers still line up
    with the original text. Quote characters stay in place.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for j in range(i, end):
                if src[j] != "\n":
                    out[j] = " "
            i = end
        elif c in "\"'`":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                elif src[j] == "\n" and c != "`":
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if src[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def _string_literals(src, start):
    """Yield (offset, text) of string literals in the call whose '(' ends at start."""
    depth, i, n = 1, start, len(src)
    while i < n and depth:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c in "\"'`":
            j = i + 1
            chunk = []
            while j < n and src[j] != c:
                if src[j] == "\\" and j + 1 < n:
                    chunk.append(src[j + 1])
                    j += 2
                    continue
                chunk.append(src[j])
                j += 1
            yield i, "".join(chunk)
            i = j
        i += 1


def scan_vocabulary(root):
    problems = []

    def report(path, line, text):
        for m in BANNED.finditer(text):
            problems.append(f"{path}:{line}: banned term {m.group(0)!r} in {text.strip()!r}")

    for path in walk(root, SOURCE_EXTS):
        src = read(path)
        code = blank_code(src)
        for call in TR_CALL.finditer(code):
            for offset, literal in _string_literals(src, call.end()):
                report(path, line_of(src, offset), literal)

    for path in walk(root, (".ts",)):
        try:
            tree = ET.parse(path)
        except ET.ParseError as exc:
            problems.append(f"{path}: unreadable: {exc}")
            continue
        for tag in ("source", "translation", "numerusform"):
            for el in tree.getroot().iter(tag):
                # A plural <translation> holds only whitespace as its own
                # text; each <numerusform> is visited on its own.
                report(path, 0, el.text or "")

    for path in walk(root, (".md",)):
        for number, line in enumerate(read(path).splitlines(), start=1):
            report(path, number, line)

    return problems


def _matching_brace(code, open_at):
    depth = 0
    for i in range(open_at, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code)


def _own_body(code, open_at, close_at):
    """Body of the block at depth 1 only: nested blocks are removed."""
    out, depth = [], 0
    for c in code[open_at + 1:close_at]:
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif depth == 0:
            out.append(c)
    return "".join(out)


def scan_plaintext(root):
    problems = []
    src_dir = os.path.join(root, "src")
    if not os.path.isdir(src_dir):
        return problems
    for path in walk(root, (".qml",), under="src"):
        code = blank_code(read(path))
        for m in NON_PLAIN_FORMAT.finditer(code):
            problems.append(
                f"{path}:{line_of(code, m.start())}: non-plain text format {m.group(0)}"
            )
        for m in TEXT_OBJECT.finditer(code):
            open_at = m.end() - 1
            close_at = _matching_brace(code, open_at)
            if not PLAIN_FORMAT.search(_own_body(code, open_at, close_at)):
                problems.append(
                    f"{path}:{line_of(code, m.start())}: {m.group(1)} without "
                    "textFormat: Text.PlainText (use PlainLabel)"
                )
    return problems


def main(argv):
    args = [a for a in argv if a != "--plaintext"]
    plaintext = "--plaintext" in argv
    if len(args) != 1 or not os.path.isdir(args[0]):
        print("usage: check_vocabulary.py ROOT [--plaintext]", file=sys.stderr)
        return 2
    root = args[0]

    problems = scan_vocabulary(root)
    if plaintext:
        problems += scan_plaintext(root)
    if problems:
        print("\n".join(problems))
        print(f"{len(problems)} problem(s) found", file=sys.stderr)
        return 1
    print("VOCABULARY_CLEAN")
    if plaintext:
        print("PLAINTEXT_CLEAN")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
