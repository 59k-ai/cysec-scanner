// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "scanevent.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QList>

#include <optional>

// NdjsonParser decodes one complete NDJSON line into a ScanEvent. An unknown
// event kind yields kind == Unknown; a malformed line yields std::nullopt.
//
// NdjsonLineBuffer splits a byte stream into complete lines. A line longer
// than kMaxLineBytes is discarded and overflowed() reports it, so a runaway
// child process cannot grow GUI memory without bound.
//
// Contract fixed by plan 13-07; implemented and tested in plan 13-09.

class NdjsonParser
{
public:
    static std::optional<ScanEvent> parseLine(QByteArrayView line);
};

class NdjsonLineBuffer
{
public:
    static constexpr qsizetype kMaxLineBytes = 1 << 20;

    // Returns the complete lines contained in the buffered data, with a
    // trailing CR trimmed. Partial trailing data stays buffered.
    QList<QByteArray> append(const QByteArray &chunk);

    bool overflowed() const;
    void reset();

private:
    QByteArray m_pending;
    bool m_overflowed = false;
    bool m_discarding = false;
};
