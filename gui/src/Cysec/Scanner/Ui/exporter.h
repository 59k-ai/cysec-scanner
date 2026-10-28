// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hostmodel.h"
#include "scanevent.h"

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>
#include <QUrl>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

// Exporter writes scan results to a user-chosen file: the engine's JSON
// payload copied verbatim, or a CSV of the host table. CSV cells follow
// RFC 4180 and are guarded against spreadsheet formula injection, because
// hostnames and banners come from the network.
//
// Contract fixed by plan 13-07; implemented in plan 13-11.
class Exporter : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit Exporter(QObject *parent = nullptr);

    static QString csvCell(const QString &value);
    static QByteArray csvForHosts(const QList<HostFact> &hosts, bool partial);

    // cysec-scan-YYYYMMDD-HHMMSS[-partial].json|csv
    Q_INVOKABLE QString defaultFileName(const QString &format, bool partial) const;
    // {ok, error}
    Q_INVOKABLE QVariantMap exportJson(const QString &payloadPath, const QUrl &target) const;
    Q_INVOKABLE QVariantMap exportCsv(HostModel *hosts, bool partial, const QUrl &target) const;
    Q_INVOKABLE void showInFolder(const QUrl &file) const;
};
