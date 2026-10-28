// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QAbstractItemModel>
#include <QAbstractTableModel>
#include <QList>
#include <QPointer>
#include <QStringList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

// HostTableAdapter turns a role-based list model (the filter proxy) into a
// table for TableView: column N shows the source role named columnRoles[N]
// as Qt::DisplayRole. rowData() returns the whole row for the detail panel.
//
// Contract fixed by plan 13-07; implemented in plan 13-10.
class HostTableAdapter : public QAbstractTableModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QAbstractItemModel *sourceModel READ sourceModel WRITE setSourceModel NOTIFY sourceModelChanged FINAL)
    Q_PROPERTY(QStringList columnRoles READ columnRoles WRITE setColumnRoles NOTIFY columnRolesChanged FINAL)

public:
    explicit HostTableAdapter(QObject *parent = nullptr);

    QAbstractItemModel *sourceModel() const;
    void setSourceModel(QAbstractItemModel *model);

    QStringList columnRoles() const;
    void setColumnRoles(const QStringList &roles);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    Q_INVOKABLE QVariantMap rowData(int row) const;

signals:
    void sourceModelChanged();
    void columnRolesChanged();

private:
    void resolveRoles();
    void connectSource();

    QPointer<QAbstractItemModel> m_source;
    QStringList m_columnRoles;
    // Plan 13-10 additions (private only): column -> source role id (-1 if
    // the source has no role of that name), the "host" role, connections.
    QList<int> m_roleIds;
    int m_hostRole = -1;
    QList<QMetaObject::Connection> m_connections;
};
