// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QDateTime>
#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

// Formatter renders numbers, percentages and times in the active UI
// language. Callers pass LanguageController.revision so bindings re-run on a
// language switch. elapsed() is locale-independent (mm:ss or h:mm:ss, ASCII
// digits) so the progress timer never changes width.
//
// Contract fixed by plan 13-07; implemented in plan 13-12.
class Formatter : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit Formatter(QObject *parent = nullptr);

    Q_INVOKABLE QString count(int n, int revision) const;
    Q_INVOKABLE QString percent(double ratio, int revision) const;
    Q_INVOKABLE QString elapsed(int seconds) const;
    Q_INVOKABLE QString logTime(const QDateTime &t, int revision) const;
};
