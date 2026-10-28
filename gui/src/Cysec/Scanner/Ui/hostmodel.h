// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "scanevent.h"

#include <QAbstractListModel>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QStringList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class QTimer;

// HostModel holds one row per discovered host. Live host events are
// coalesced and flushed to views every 100 ms so a fast scan does not
// thrash the table; the final payload is reconciled in afterwards.
//
// Contract fixed by plan 13-07; implemented in plan 13-10.
class HostModel : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(int count READ count NOTIFY countChanged FINAL)

public:
    enum Roles {
        IpRole = Qt::UserRole + 1,
        HostnameRole,
        VendorRole,
        MacRole,
        PortsRole,      // compact, e.g. "22, 80, 443 +3"
        PortsListRole,  // e.g. "22/tcp 80/tcp"
        OsGuessRole,
        ExternalIdRole,
        ServicesRole,   // QVariantList of maps
        SortKeyRole,    // quint32 IPv4
        HostRole,       // QVariantMap of all fields
    };
    Q_ENUM(Roles)

    explicit HostModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    void upsert(const HostFact &fact);
    void flushNow();
    // Returns true if any row changed.
    bool reconcileFromPayload(const QByteArray &payloadJson);
    void clear();
    int count() const;

    Q_INVOKABLE QVariantMap hostAt(int row) const;

    // For export.
    QList<HostFact> hosts() const;

signals:
    void countChanged();

private:
    // Row key: the IP, or "id:<external_id>" for assets without an IP.
    static QString keyOf(const HostFact &fact);
    void rebuildIndex();

    QList<HostFact> m_hosts;
    // Plan 13-10 additions (private only; the public contract is unchanged).
    QHash<QString, int> m_index;             // key -> row in m_hosts
    QHash<QString, HostFact> m_pending;      // coalesced, not yet visible
    QStringList m_pendingOrder;              // arrival order of pending keys
    QTimer *m_flushTimer = nullptr;
};
