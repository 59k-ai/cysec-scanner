// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hostfilterproxy.h"

#include "hostmodel.h"

// Sorting is by role name so QML never handles role numbers; "ip" sorts on
// the numeric sortKey role so 192.0.2.9 comes before 192.0.2.10. The text
// filter is a case-insensitive substring match over the observed facts:
// IP, hostname, vendor, MAC, port list, OS guess and service names/products.

HostFilterProxy::HostFilterProxy(QObject *parent)
    : QSortFilterProxyModel(parent)
{
    setDynamicSortFilter(true);
}

QString HostFilterProxy::filterText() const
{
    return m_filterText;
}

void HostFilterProxy::setFilterText(const QString &text)
{
    if (text == m_filterText)
        return;
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
    beginFilterChange();
    m_filterText = text;
    endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
    m_filterText = text;
    invalidateRowsFilter();
#endif
    emit filterTextChanged();
}

void HostFilterProxy::sortByRole(const QString &roleName, Qt::SortOrder order)
{
    if (!sourceModel())
        return;
    const QByteArray wanted = roleName == QStringLiteral("ip") ? QByteArrayLiteral("sortKey")
                                                                : roleName.toUtf8();
    const QHash<int, QByteArray> names = sourceModel()->roleNames();
    for (auto it = names.cbegin(); it != names.cend(); ++it) {
        if (it.value() == wanted) {
            setSortRole(it.key());
            sort(0, order);
            return;
        }
    }
}

QVariantMap HostFilterProxy::hostAt(int proxyRow) const
{
    if (proxyRow < 0 || proxyRow >= rowCount())
        return {};
    return index(proxyRow, 0).data(HostModel::HostRole).toMap();
}

bool HostFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    const QString needle = m_filterText.trimmed();
    if (needle.isEmpty() || !sourceModel())
        return true;
    const QModelIndex idx = sourceModel()->index(sourceRow, 0, sourceParent);
    auto matches = [&needle](const QVariant &v) {
        return v.toString().contains(needle, Qt::CaseInsensitive);
    };
    for (int role : {int(HostModel::IpRole), int(HostModel::HostnameRole),
                     int(HostModel::VendorRole), int(HostModel::MacRole),
                     int(HostModel::PortsListRole), int(HostModel::OsGuessRole)}) {
        if (matches(idx.data(role)))
            return true;
    }
    const QVariantList services = idx.data(HostModel::ServicesRole).toList();
    for (const QVariant &sv : services) {
        const QVariantMap s = sv.toMap();
        if (matches(s.value(QStringLiteral("serviceName")))
            || matches(s.value(QStringLiteral("product")))) {
            return true;
        }
    }
    return false;
}

bool HostFilterProxy::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    const QVariant l = left.data(sortRole());
    const QVariant r = right.data(sortRole());
    auto numeric = [](const QVariant &v) {
        switch (v.typeId()) {
        case QMetaType::Int:
        case QMetaType::UInt:
        case QMetaType::LongLong:
        case QMetaType::ULongLong:
        case QMetaType::Double:
            return true;
        default:
            return false;
        }
    };
    if (numeric(l) && numeric(r)) {
        if (l.toDouble() != r.toDouble())
            return l.toDouble() < r.toDouble();
    } else {
        const int c = QString::compare(l.toString(), r.toString(), Qt::CaseInsensitive);
        if (c != 0)
            return c < 0;
    }
    // Ties fall back to numeric IP order so equal keys sort stably.
    return left.data(HostModel::SortKeyRole).toUInt() < right.data(HostModel::SortKeyRole).toUInt();
}
