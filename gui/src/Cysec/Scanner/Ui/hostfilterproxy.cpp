// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hostfilterproxy.h"

// Compile-only skeleton; plan 13-10 implements filtering and sorting.

HostFilterProxy::HostFilterProxy(QObject *parent)
    : QSortFilterProxyModel(parent)
{
}

QString HostFilterProxy::filterText() const
{
    return m_filterText;
}

void HostFilterProxy::setFilterText(const QString &text)
{
    if (text == m_filterText)
        return;
    m_filterText = text;
    emit filterTextChanged();
}

void HostFilterProxy::sortByRole(const QString &roleName, Qt::SortOrder order)
{
    Q_UNUSED(roleName);
    Q_UNUSED(order);
}

QVariantMap HostFilterProxy::hostAt(int proxyRow) const
{
    Q_UNUSED(proxyRow);
    return {};
}

bool HostFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    return QSortFilterProxyModel::filterAcceptsRow(sourceRow, sourceParent);
}

bool HostFilterProxy::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    return QSortFilterProxyModel::lessThan(left, right);
}
