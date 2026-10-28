// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hosttableadapter.h"

// Compile-only skeleton; plan 13-10 implements the adapter.

HostTableAdapter::HostTableAdapter(QObject *parent)
    : QAbstractTableModel(parent)
{
}

QAbstractItemModel *HostTableAdapter::sourceModel() const
{
    return m_source;
}

void HostTableAdapter::setSourceModel(QAbstractItemModel *model)
{
    if (model == m_source)
        return;
    m_source = model;
    emit sourceModelChanged();
}

QStringList HostTableAdapter::columnRoles() const
{
    return m_columnRoles;
}

void HostTableAdapter::setColumnRoles(const QStringList &roles)
{
    if (roles == m_columnRoles)
        return;
    m_columnRoles = roles;
    emit columnRolesChanged();
}

int HostTableAdapter::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return 0;
}

int HostTableAdapter::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return 0;
}

QVariant HostTableAdapter::data(const QModelIndex &index, int role) const
{
    Q_UNUSED(index);
    Q_UNUSED(role);
    return {};
}

QVariantMap HostTableAdapter::rowData(int row) const
{
    Q_UNUSED(row);
    return {};
}
