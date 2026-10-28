// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "validators.h"

// Compile-only skeleton; plan 13-11 implements validation.

QString Ipv4Prefix::toString() const
{
    return {};
}

Validators::Validators(QObject *parent)
    : QObject(parent)
{
}

std::optional<Ipv4Prefix> Validators::parseScopeEntry(QStringView entry)
{
    Q_UNUSED(entry);
    return std::nullopt;
}

bool Validators::parsePortSpec(QStringView spec, QList<int> *out)
{
    Q_UNUSED(spec);
    Q_UNUSED(out);
    return false;
}

bool Validators::contains(const Ipv4Prefix &outer, const Ipv4Prefix &inner)
{
    Q_UNUSED(outer);
    Q_UNUSED(inner);
    return false;
}

QVariantMap Validators::validateTargets(const QString &text) const
{
    Q_UNUSED(text);
    return {{QStringLiteral("ok"), false}};
}

QVariantMap Validators::validatePorts(const QString &text) const
{
    Q_UNUSED(text);
    return {{QStringLiteral("ok"), false}};
}

bool Validators::requiresAuthorisation(const QStringList &cidrs, const QStringList &localCidrs) const
{
    Q_UNUSED(cidrs);
    Q_UNUSED(localCidrs);
    return false;
}
