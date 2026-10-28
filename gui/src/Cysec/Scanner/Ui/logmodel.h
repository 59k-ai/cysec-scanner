// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QAbstractListModel>
#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QtQml/qqmlregistration.h>

// LogModel is the bounded scan log shown in the log panel. It keeps at most
// kCap lines (oldest dropped first) and counts warnings and errors so the
// panel header can summarise them without scanning the rows.
//
// Contract fixed by plan 13-07; implemented in plan 13-10.
class LogModel : public QAbstractListModel
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(int warningCount READ warningCount NOTIFY warningCountChanged FINAL)
    Q_PROPERTY(int errorCount READ errorCount NOTIFY errorCountChanged FINAL)
    Q_PROPERTY(int count READ count NOTIFY countChanged FINAL)

public:
    enum Roles { TimeRole = Qt::UserRole + 1, LevelRole, TextRole };
    Q_ENUM(Roles)

    static constexpr int kCap = 5000;

    explicit LogModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    void append(const QString &level, const QString &text,
                const QDateTime &when = QDateTime::currentDateTime());
    void clear();

    int warningCount() const;
    int errorCount() const;
    int count() const;

signals:
    void warningCountChanged();
    void errorCountChanged();
    void countChanged();

private:
    struct Line
    {
        QDateTime when;
        QString level;
        QString text;
    };

    QList<Line> m_lines;
    int m_warningCount = 0;
    int m_errorCount = 0;
};
