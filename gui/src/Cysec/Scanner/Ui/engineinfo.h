// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

// EngineInfo asks the engine to describe itself (version, host
// capabilities, local networks, default ports, timing tiers) and exposes the
// answer to QML. failed is set when the engine cannot be found or its answer
// cannot be decoded; the setup bar then disables Start.
//
// Contract fixed by plan 13-07; implemented in plan 13-13.
class EngineInfo : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(bool loaded READ loaded NOTIFY changed FINAL)
    Q_PROPERTY(bool failed READ failed NOTIFY changed FINAL)
    Q_PROPERTY(QString engineVersion READ engineVersion NOTIFY changed FINAL)
    Q_PROPERTY(bool unprivilegedIcmp READ unprivilegedIcmp NOTIFY changed FINAL)
    Q_PROPERTY(bool systemPing READ systemPing NOTIFY changed FINAL)
    Q_PROPERTY(bool arpCache READ arpCache NOTIFY changed FINAL)
    Q_PROPERTY(QVariantList networks READ networks NOTIFY changed FINAL) // [{interface, cidr}]
    Q_PROPERTY(QList<int> defaultPorts READ defaultPorts NOTIFY changed FINAL)
    Q_PROPERTY(QStringList timingTiers READ timingTiers NOTIFY changed FINAL)
    Q_PROPERTY(QStringList localCidrs READ localCidrs NOTIFY changed FINAL)
    Q_PROPERTY(QString guiVersion READ guiVersion CONSTANT FINAL)
    Q_PROPERTY(QString qtVersion READ qtVersion CONSTANT FINAL)

public:
    explicit EngineInfo(QObject *parent = nullptr);

    bool loaded() const;
    bool failed() const;
    QString engineVersion() const;
    bool unprivilegedIcmp() const;
    bool systemPing() const;
    bool arpCache() const;
    QVariantList networks() const;
    QList<int> defaultPorts() const;
    QStringList timingTiers() const;
    QStringList localCidrs() const;
    QString guiVersion() const;
    QString qtVersion() const;

    Q_INVOKABLE void refresh();

    // Returns true if the describe output decoded; tests feed it directly.
    bool loadFromJson(const QByteArray &describeJson);
    void setEnginePath(const QString &p);

signals:
    void changed();

private:
    QString m_enginePath;
    bool m_loaded = false;
    bool m_failed = false;
    QString m_engineVersion;
    bool m_unprivilegedIcmp = false;
    bool m_systemPing = false;
    bool m_arpCache = false;
    QVariantList m_networks;
    QList<int> m_defaultPorts;
    QStringList m_timingTiers;
    QStringList m_localCidrs;
};
