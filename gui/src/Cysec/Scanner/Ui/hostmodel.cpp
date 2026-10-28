// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hostmodel.h"

// Compile-only skeleton; plan 13-10 implements the model.

HostModel::HostModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

int HostModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return int(m_hosts.size());
}

QVariant HostModel::data(const QModelIndex &index, int role) const
{
    Q_UNUSED(index);
    Q_UNUSED(role);
    return {};
}

QHash<int, QByteArray> HostModel::roleNames() const
{
    return {};
}

void HostModel::upsert(const HostFact &fact)
{
    Q_UNUSED(fact);
}

void HostModel::flushNow()
{
}

bool HostModel::reconcileFromPayload(const QByteArray &payloadJson)
{
    Q_UNUSED(payloadJson);
    return false;
}

void HostModel::clear()
{
}

int HostModel::count() const
{
    return int(m_hosts.size());
}

QVariantMap HostModel::hostAt(int row) const
{
    Q_UNUSED(row);
    return {};
}

QList<HostFact> HostModel::hosts() const
{
    return m_hosts;
}
