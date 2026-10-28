// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "formatter.h"

// Compile-only skeleton; plan 13-12 implements formatting.

Formatter::Formatter(QObject *parent)
    : QObject(parent)
{
}

QString Formatter::count(int n, int revision) const
{
    Q_UNUSED(n);
    Q_UNUSED(revision);
    return {};
}

QString Formatter::percent(double ratio, int revision) const
{
    Q_UNUSED(ratio);
    Q_UNUSED(revision);
    return {};
}

QString Formatter::elapsed(int seconds) const
{
    Q_UNUSED(seconds);
    return {};
}

QString Formatter::logTime(const QDateTime &t, int revision) const
{
    Q_UNUSED(t);
    Q_UNUSED(revision);
    return {};
}
