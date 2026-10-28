// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hosttableadapter.h"

#include <QPersistentModelIndex>

#include <memory>

// Column N of the table shows source role columnRoles[N] as DisplayRole, so
// Phase 14 adds columns from QML without touching C++. Rows map 1:1 to the
// source's top-level rows; every structural source signal is forwarded so
// TableView keeps its delegates and selection across live inserts, filter
// changes and re-sorts. Header titles come from the QML column list.

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
    beginResetModel();
    for (const QMetaObject::Connection &c : std::as_const(m_connections))
        disconnect(c);
    m_connections.clear();
    m_source = model;
    connectSource();
    resolveRoles();
    endResetModel();
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
    beginResetModel();
    m_columnRoles = roles;
    resolveRoles();
    endResetModel();
    emit columnRolesChanged();
}

void HostTableAdapter::resolveRoles()
{
    m_roleIds.clear();
    m_hostRole = -1;
    QHash<QByteArray, int> byName;
    if (m_source) {
        const QHash<int, QByteArray> names = m_source->roleNames();
        for (auto it = names.cbegin(); it != names.cend(); ++it)
            byName.insert(it.value(), it.key());
    }
    for (const QString &role : std::as_const(m_columnRoles))
        m_roleIds.append(byName.value(role.toUtf8(), -1));
    m_hostRole = byName.value(QByteArrayLiteral("host"), -1);
}

void HostTableAdapter::connectSource()
{
    QAbstractItemModel *src = m_source;
    if (!src)
        return;

    m_connections << connect(src, &QAbstractItemModel::rowsAboutToBeInserted, this,
                             [this](const QModelIndex &parent, int first, int last) {
                                 if (!parent.isValid())
                                     beginInsertRows(QModelIndex(), first, last);
                             });
    m_connections << connect(src, &QAbstractItemModel::rowsInserted, this,
                             [this](const QModelIndex &parent) {
                                 if (!parent.isValid())
                                     endInsertRows();
                             });
    m_connections << connect(src, &QAbstractItemModel::rowsAboutToBeRemoved, this,
                             [this](const QModelIndex &parent, int first, int last) {
                                 if (!parent.isValid())
                                     beginRemoveRows(QModelIndex(), first, last);
                             });
    m_connections << connect(src, &QAbstractItemModel::rowsRemoved, this,
                             [this](const QModelIndex &parent) {
                                 if (!parent.isValid())
                                     endRemoveRows();
                             });
    m_connections << connect(src, &QAbstractItemModel::rowsAboutToBeMoved, this,
                             [this](const QModelIndex &srcParent, int first, int last,
                                    const QModelIndex &dstParent, int dest) {
                                 if (!srcParent.isValid() && !dstParent.isValid())
                                     beginMoveRows(QModelIndex(), first, last, QModelIndex(), dest);
                             });
    m_connections << connect(src, &QAbstractItemModel::rowsMoved, this,
                             [this](const QModelIndex &srcParent, int, int,
                                    const QModelIndex &dstParent) {
                                 if (!srcParent.isValid() && !dstParent.isValid())
                                     endMoveRows();
                             });
    m_connections << connect(src, &QAbstractItemModel::modelAboutToBeReset, this,
                             [this] { beginResetModel(); });
    m_connections << connect(src, &QAbstractItemModel::modelReset, this, [this] {
        resolveRoles();
        endResetModel();
    });

    // Re-sorts arrive as layout changes. Track every persistent adapter index
    // through a persistent source index so selection follows the row.
    auto tracked = std::make_shared<QList<QPair<QPersistentModelIndex, QPersistentModelIndex>>>();
    m_connections << connect(src, &QAbstractItemModel::layoutAboutToBeChanged, this,
                             [this, tracked] {
                                 emit layoutAboutToBeChanged();
                                 tracked->clear();
                                 const QModelIndexList mine = persistentIndexList();
                                 for (const QModelIndex &idx : mine) {
                                     tracked->append({QPersistentModelIndex(idx),
                                                      QPersistentModelIndex(
                                                          m_source->index(idx.row(), 0))});
                                 }
                             });
    m_connections << connect(src, &QAbstractItemModel::layoutChanged, this, [this, tracked] {
        for (const auto &pair : std::as_const(*tracked)) {
            const QModelIndex to = pair.second.isValid()
                                       ? index(pair.second.row(), pair.first.column())
                                       : QModelIndex();
            changePersistentIndex(pair.first, to);
        }
        tracked->clear();
        emit layoutChanged();
    });

    m_connections << connect(src, &QAbstractItemModel::dataChanged, this,
                             [this](const QModelIndex &topLeft, const QModelIndex &bottomRight) {
                                 if (topLeft.parent().isValid() || m_columnRoles.isEmpty())
                                     return;
                                 emit dataChanged(index(topLeft.row(), 0),
                                                  index(bottomRight.row(),
                                                        int(m_columnRoles.size()) - 1));
                             });
    m_connections << connect(src, &QObject::destroyed, this, [this] {
        beginResetModel();
        m_connections.clear();
        m_source = nullptr;
        resolveRoles();
        endResetModel();
        emit sourceModelChanged();
    });
}

int HostTableAdapter::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid() || !m_source)
        return 0;
    return m_source->rowCount();
}

int HostTableAdapter::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return int(m_columnRoles.size());
}

QVariant HostTableAdapter::data(const QModelIndex &index, int role) const
{
    if (role != Qt::DisplayRole || !m_source || !index.isValid() || index.parent().isValid()
        || index.row() >= m_source->rowCount() || index.column() >= m_columnRoles.size()) {
        return {};
    }
    const int sourceRole = m_roleIds.value(index.column(), -1);
    if (sourceRole < 0)
        return {};
    return m_source->index(index.row(), 0).data(sourceRole);
}

QVariantMap HostTableAdapter::rowData(int row) const
{
    if (!m_source || m_hostRole < 0 || row < 0 || row >= m_source->rowCount())
        return {};
    return m_source->index(row, 0).data(m_hostRole).toMap();
}
