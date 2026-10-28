// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "logmodel.h"

// Compile-only skeleton; plan 13-10 implements the model.

LogModel::LogModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

int LogModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return int(m_lines.size());
}

QVariant LogModel::data(const QModelIndex &index, int role) const
{
    Q_UNUSED(index);
    Q_UNUSED(role);
    return {};
}

QHash<int, QByteArray> LogModel::roleNames() const
{
    return {};
}

void LogModel::append(const QString &level, const QString &text, const QDateTime &when)
{
    Q_UNUSED(level);
    Q_UNUSED(text);
    Q_UNUSED(when);
}

void LogModel::clear()
{
}

int LogModel::warningCount() const
{
    return m_warningCount;
}

int LogModel::errorCount() const
{
    return m_errorCount;
}

int LogModel::count() const
{
    return int(m_lines.size());
}
