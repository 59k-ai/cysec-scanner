// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QStringView>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <optional>

// An IPv4 network, host bits masked off.
struct Ipv4Prefix
{
    quint32 addr = 0;
    int prefixLen = 32;
    QString toString() const;
};

// Validators checks setup-bar input with the same rules the engine applies,
// so the GUI rejects what the engine would reject before a scan starts.
// Scope entries mirror the engine's prefix-or-address parsing (then masked);
// port specs mirror its port-list parsing.
//
// Contract fixed by plan 13-07; implemented in plan 13-11.
class Validators : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    enum Error { Ok, Empty, InvalidTarget, InvalidPorts };
    Q_ENUM(Error)

    explicit Validators(QObject *parent = nullptr);

    static std::optional<Ipv4Prefix> parseScopeEntry(QStringView entry);
    static bool parsePortSpec(QStringView spec, QList<int> *out);
    static bool contains(const Ipv4Prefix &outer, const Ipv4Prefix &inner);

    // {ok, error, cidrs (normalised)}
    Q_INVOKABLE QVariantMap validateTargets(const QString &text) const;
    // {ok, error}
    Q_INVOKABLE QVariantMap validatePorts(const QString &text) const;
    // True when any target lies outside every local network.
    Q_INVOKABLE bool requiresAuthorisation(const QStringList &cidrs,
                                           const QStringList &localCidrs) const;
};
