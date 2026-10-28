// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "appearance.h"

#include <QGuiApplication>
#include <QStyleHints>
#include <QtGlobal>

Appearance::Appearance(QObject *parent)
    : QObject(parent)
{
    // Qt 6.8 has no portable reduced-motion query, so the environment is the
    // override for tests and for users who need it.
    m_reducedMotion = qgetenv("CYSEC_SCANNER_REDUCED_MOTION") == "1";
    m_fontScale = parseFontScale(qgetenv("CYSEC_SCANNER_FONT_SCALE"));

    if (auto *hints = QGuiApplication::styleHints()) {
        connect(hints, &QStyleHints::colorSchemeChanged, this, &Appearance::refreshDark);
    }
    refreshDark();
}

bool Appearance::dark() const
{
    return m_dark;
}

void Appearance::setForcedScheme(Scheme scheme)
{
    if (scheme == m_forcedScheme)
        return;
    m_forcedScheme = scheme;
    emit forcedSchemeChanged();
    refreshDark();
}

void Appearance::setReducedMotion(bool reduced)
{
    if (reduced == m_reducedMotion)
        return;
    m_reducedMotion = reduced;
    emit reducedMotionChanged();
}

void Appearance::setFontScale(qreal scale)
{
    const qreal clamped = qBound(1.0, scale, 2.0);
    if (qFuzzyCompare(clamped, m_fontScale))
        return;
    m_fontScale = clamped;
    emit fontScaleChanged();
}

qreal Appearance::parseFontScale(const QByteArray &raw)
{
    bool ok = false;
    const double value = raw.trimmed().toDouble(&ok);
    if (!ok || qIsNaN(value))
        return 1.0;
    return qBound(1.0, value, 2.0);
}

void Appearance::refreshDark()
{
    bool next = false;
    switch (m_forcedScheme) {
    case Light:
        next = false;
        break;
    case Dark:
        next = true;
        break;
    case Auto:
        if (const auto *hints = QGuiApplication::styleHints())
            next = hints->colorScheme() == Qt::ColorScheme::Dark;
        break;
    }
    if (next == m_dark)
        return;
    m_dark = next;
    emit darkChanged();
}
