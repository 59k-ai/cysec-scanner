// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "engineinfo.h"

#include <QtGlobal>

// Compile-only skeleton; plan 13-13 implements the describe call.

EngineInfo::EngineInfo(QObject *parent)
    : QObject(parent)
{
}

bool EngineInfo::loaded() const
{
    return m_loaded;
}

bool EngineInfo::failed() const
{
    return m_failed;
}

QString EngineInfo::engineVersion() const
{
    return m_engineVersion;
}

bool EngineInfo::unprivilegedIcmp() const
{
    return m_unprivilegedIcmp;
}

bool EngineInfo::systemPing() const
{
    return m_systemPing;
}

bool EngineInfo::arpCache() const
{
    return m_arpCache;
}

QVariantList EngineInfo::networks() const
{
    return m_networks;
}

QList<int> EngineInfo::defaultPorts() const
{
    return m_defaultPorts;
}

QStringList EngineInfo::timingTiers() const
{
    return m_timingTiers;
}

QStringList EngineInfo::localCidrs() const
{
    return m_localCidrs;
}

QString EngineInfo::guiVersion() const
{
    return QStringLiteral(CYSEC_SCANNER_GUI_VERSION);
}

QString EngineInfo::qtVersion() const
{
    return QString::fromLatin1(qVersion());
}

void EngineInfo::refresh()
{
}

bool EngineInfo::loadFromJson(const QByteArray &describeJson)
{
    Q_UNUSED(describeJson);
    return false;
}

void EngineInfo::setEnginePath(const QString &p)
{
    m_enginePath = p;
}
