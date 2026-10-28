// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "formatter.h"

#include <QLocale>
#include <QtMath>

// Every locale-dependent value reads the default QLocale(), which
// LanguageController sets with QLocale::setDefault on a language switch.
// Formatter never reads settings or the controller; the revision argument
// exists only so QML bindings re-evaluate after a switch. No text is
// translated here: only numbers and times.

namespace {

// QLocale exposes the percent sign but not the CLDR percent pattern. These
// languages separate the number from the sign (German per DIN 5008); a
// no-break space keeps "13 %" on one line.
bool spacesPercentSign(QLocale::Language language)
{
    switch (language) {
    case QLocale::German:
    case QLocale::French:
    case QLocale::Spanish:
    case QLocale::Romanian:
    case QLocale::Swedish:
    case QLocale::Danish:
    case QLocale::Finnish:
    case QLocale::NorwegianBokmal:
    case QLocale::Czech:
        return true;
    default:
        return false;
    }
}

} // namespace

Formatter::Formatter(QObject *parent)
    : QObject(parent)
{
}

QString Formatter::count(int n, int revision) const
{
    Q_UNUSED(revision);
    return QLocale().toString(n);
}

QString Formatter::percent(double ratio, int revision) const
{
    Q_UNUSED(revision);
    double clamped = ratio;
    if (qIsNaN(clamped) || clamped < 0.0)
        clamped = 0.0;
    else if (clamped > 1.0)
        clamped = 1.0;
    const QLocale loc;
    QString out = loc.toString(qRound(clamped * 100.0));
    if (spacesPercentSign(loc.language()))
        out += QChar(0x00A0);
    out += loc.percent();
    return out;
}

QString Formatter::elapsed(int seconds) const
{
    // ASCII digits in every language so the timer keeps a fixed width.
    const int s = qMax(0, seconds);
    const int hours = s / 3600;
    const int minutes = (s % 3600) / 60;
    const int secs = s % 60;
    const QChar zero = QLatin1Char('0');
    if (hours > 0) {
        return QStringLiteral("%1:%2:%3")
            .arg(hours)
            .arg(minutes, 2, 10, zero)
            .arg(secs, 2, 10, zero);
    }
    return QStringLiteral("%1:%2").arg(minutes, 2, 10, zero).arg(secs, 2, 10, zero);
}

QString Formatter::logTime(const QDateTime &t, int revision) const
{
    Q_UNUSED(revision);
    if (!t.isValid())
        return {};
    return QLocale().toString(t.time(), QLocale::ShortFormat);
}
