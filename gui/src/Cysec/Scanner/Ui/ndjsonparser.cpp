// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "ndjsonparser.h"

// Compile-only skeleton; plan 13-09 implements decoding and line splitting.

std::optional<ScanEvent> NdjsonParser::parseLine(QByteArrayView line)
{
    Q_UNUSED(line);
    return std::nullopt;
}

QList<QByteArray> NdjsonLineBuffer::append(const QByteArray &chunk)
{
    Q_UNUSED(chunk);
    return {};
}

bool NdjsonLineBuffer::overflowed() const
{
    return m_overflowed;
}

void NdjsonLineBuffer::reset()
{
    m_pending.clear();
    m_overflowed = false;
    m_discarding = false;
}
