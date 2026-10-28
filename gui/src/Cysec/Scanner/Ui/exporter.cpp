// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "exporter.h"

// Compile-only skeleton; plan 13-11 implements export.

Exporter::Exporter(QObject *parent)
    : QObject(parent)
{
}

QString Exporter::csvCell(const QString &value)
{
    Q_UNUSED(value);
    return {};
}

QByteArray Exporter::csvForHosts(const QList<HostFact> &hosts, bool partial)
{
    Q_UNUSED(hosts);
    Q_UNUSED(partial);
    return {};
}

QString Exporter::defaultFileName(const QString &format, bool partial) const
{
    Q_UNUSED(format);
    Q_UNUSED(partial);
    return {};
}

QVariantMap Exporter::exportJson(const QString &payloadPath, const QUrl &target) const
{
    Q_UNUSED(payloadPath);
    Q_UNUSED(target);
    return {{QStringLiteral("ok"), false}};
}

QVariantMap Exporter::exportCsv(HostModel *hosts, bool partial, const QUrl &target) const
{
    Q_UNUSED(hosts);
    Q_UNUSED(partial);
    Q_UNUSED(target);
    return {{QStringLiteral("ok"), false}};
}

void Exporter::showInFolder(const QUrl &file) const
{
    Q_UNUSED(file);
}
