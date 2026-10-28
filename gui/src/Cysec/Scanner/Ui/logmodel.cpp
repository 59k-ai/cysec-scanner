// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "logmodel.h"

// The log is the record of the scan, so it is bounded (kCap lines, oldest
// dropped first, T-13-35) but its warning/error counters are cumulative and
// survive the drop. The engine already sanitises messages; control
// characters other than tab are stripped again here as defence in depth.
// Markup such as "<b>" is stored verbatim: the panel renders plain text.

namespace {

QString normaliseLevel(const QString &level)
{
    const QString l = level.trimmed().toLower();
    if (l == QStringLiteral("warn") || l == QStringLiteral("warning"))
        return QStringLiteral("warn");
    if (l == QStringLiteral("error"))
        return QStringLiteral("error");
    return QStringLiteral("info");
}

QString stripControl(const QString &text)
{
    QString out;
    out.reserve(text.size());
    for (const QChar c : text) {
        if (c == QChar(u'\t') || c.category() != QChar::Other_Control)
            out.append(c);
    }
    return out;
}

} // namespace

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
    if (!index.isValid() || index.parent().isValid() || index.row() >= m_lines.size())
        return {};
    const Line &line = m_lines.at(index.row());
    switch (role) {
    case TimeRole:
        return line.when;
    case LevelRole:
        return line.level;
    case Qt::DisplayRole:
    case TextRole:
        return line.text;
    default:
        return {};
    }
}

QHash<int, QByteArray> LogModel::roleNames() const
{
    return {
        {TimeRole, QByteArrayLiteral("time")},
        {LevelRole, QByteArrayLiteral("level")},
        {TextRole, QByteArrayLiteral("text")},
    };
}

void LogModel::append(const QString &level, const QString &text, const QDateTime &when)
{
    const QString lvl = normaliseLevel(level);
    const bool atCap = m_lines.size() >= kCap;
    if (atCap) {
        beginRemoveRows(QModelIndex(), 0, 0);
        m_lines.removeFirst();
        endRemoveRows();
    }
    const int row = int(m_lines.size());
    beginInsertRows(QModelIndex(), row, row);
    m_lines.append(Line{when, lvl, stripControl(text)});
    endInsertRows();

    if (lvl == QStringLiteral("warn")) {
        ++m_warningCount;
        emit warningCountChanged();
    } else if (lvl == QStringLiteral("error")) {
        ++m_errorCount;
        emit errorCountChanged();
    }
    if (!atCap)
        emit countChanged();
}

void LogModel::clear()
{
    const bool hadRows = !m_lines.isEmpty();
    beginResetModel();
    m_lines.clear();
    endResetModel();
    if (m_warningCount != 0) {
        m_warningCount = 0;
        emit warningCountChanged();
    }
    if (m_errorCount != 0) {
        m_errorCount = 0;
        emit errorCountChanged();
    }
    if (hadRows)
        emit countChanged();
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
