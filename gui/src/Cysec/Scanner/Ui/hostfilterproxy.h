// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QSortFilterProxyModel>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

// HostFilterProxy filters the host model by free text (IP, hostname, vendor,
// MAC, ports, OS guess) and sorts by a role name, so QML never needs role
// numbers. IP sorting uses the numeric sort key, not the string.
//
// Contract fixed by plan 13-07; implemented in plan 13-10.
class HostFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(QString filterText READ filterText WRITE setFilterText NOTIFY filterTextChanged FINAL)

public:
    explicit HostFilterProxy(QObject *parent = nullptr);

    QString filterText() const;
    void setFilterText(const QString &text);

    Q_INVOKABLE void sortByRole(const QString &roleName, Qt::SortOrder order);
    Q_INVOKABLE QVariantMap hostAt(int proxyRow) const;

signals:
    void filterTextChanged();

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override;

private:
    QString m_filterText;
};
