// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "exporter.h"

#include <QDateTime>
#include <QDesktopServices>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QSaveFile>

// The JSON export is the engine payload exactly as the engine wrote it: it is
// parsed only to prove it is JSON, then the original bytes are written. The
// payload already carries scan_status (D-25), so no envelope is added and
// nothing is re-serialised (key order and float spelling must not drift).
//
// The CSV export has a fixed column set; scan_status is on every row so a
// partial export stays labelled even when rows are copied out of the file.
// Filenames and CSV content are never localised. Error strings are the OS
// text from QFileDevice; QML wraps them in translated messages.

namespace {

QVariantMap failure(const QString &error)
{
    return {{QStringLiteral("ok"), false}, {QStringLiteral("error"), error}};
}

QVariantMap success()
{
    return {{QStringLiteral("ok"), true}, {QStringLiteral("error"), QString()}};
}

// Atomic write: the target either holds all of data or is left untouched.
QVariantMap writeAtomically(const QUrl &target, const QByteArray &data)
{
    if (!target.isLocalFile())
        return failure(QStringLiteral("target is not a local file"));
    QSaveFile out(target.toLocalFile());
    if (!out.open(QIODevice::WriteOnly))
        return failure(out.errorString());
#ifndef Q_OS_WIN
    // Exports carry network inventory, so they are owner-only (0600). The mode
    // is set on the temp file; commit() renames it over the target, so a
    // pre-existing looser target is replaced by an owner-only file. Windows
    // relies on the parent directory's ACL inheritance instead (QFile
    // permissions only toggle the read-only attribute there).
    if (!out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        const QString err = out.errorString();
        out.cancelWriting();
        return failure(err);
    }
#endif
    if (out.write(data) != data.size()) {
        const QString err = out.errorString();
        out.cancelWriting();
        return failure(err);
    }
    if (!out.commit())
        return failure(out.errorString());
    return success();
}

bool needsFormulaGuard(const QString &value)
{
    if (value.isEmpty())
        return false;
    const QChar c = value.front();
    return c == u'=' || c == u'+' || c == u'-' || c == u'@' || c == u'\t' || c == u'\r';
}

} // namespace

Exporter::Exporter(QObject *parent)
    : QObject(parent)
{
}

QString Exporter::csvCell(const QString &value)
{
    // Guard first, then quote, so a guarded cell that also needs quoting
    // keeps the apostrophe inside the quotes.
    QString cell = needsFormulaGuard(value) ? QStringLiteral("'") + value : value;
    if (cell.contains(u'"') || cell.contains(u',') || cell.contains(u'\r')
        || cell.contains(u'\n')) {
        cell.replace(QStringLiteral("\""), QStringLiteral("\"\""));
        cell = QStringLiteral("\"") + cell + QStringLiteral("\"");
    }
    return cell;
}

QByteArray Exporter::csvForHosts(const QList<HostFact> &hosts, bool partial)
{
    static const QString crlf = QStringLiteral("\r\n");
    const QString status = partial ? QStringLiteral("partial") : QStringLiteral("complete");

    QString text = QStringLiteral("ip,hostname,mac,mac_vendor,open_ports,os_guess,scan_status")
                   + crlf;
    for (const HostFact &h : hosts) {
        QStringList ports;
        ports.reserve(h.services.size());
        for (const ServiceFact &s : h.services)
            ports.append(QString::number(s.port) + u'/' + s.protocol);

        const QStringList cells{h.ip,          h.hostname,
                                h.mac,         h.macVendor,
                                ports.join(u' '), h.osGuess,
                                status};
        QStringList row;
        row.reserve(cells.size());
        for (const QString &c : cells)
            row.append(csvCell(c));
        text += row.join(u',') + crlf;
    }
    return text.toUtf8(); // UTF-8, no BOM
}

QString Exporter::defaultFileName(const QString &format, bool partial) const
{
    const QString ext = format.toLower();
    if (ext != QLatin1StringView("json") && ext != QLatin1StringView("csv"))
        return {};
    // Fixed C-locale pattern: QDateTime::toString(QString) is not localised.
    const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"));
    return QStringLiteral("cysec-scan-") + stamp
           + (partial ? QStringLiteral("-partial") : QString()) + u'.' + ext;
}

QVariantMap Exporter::exportJson(const QString &payloadPath, const QUrl &target) const
{
    QFile in(payloadPath);
    if (!in.open(QIODevice::ReadOnly))
        return failure(in.errorString());
    const QByteArray bytes = in.readAll();
    if (in.error() != QFileDevice::NoError)
        return failure(in.errorString());

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &parseError);
    if (parseError.error != QJsonParseError::NoError)
        return failure(parseError.errorString());
    if (!doc.isObject())
        return failure(QStringLiteral("payload is not a JSON object"));

    return writeAtomically(target, bytes);
}

QVariantMap Exporter::exportCsv(HostModel *hosts, bool partial, const QUrl &target) const
{
    if (!hosts)
        return failure(QStringLiteral("no host data"));
    return writeAtomically(target, csvForHosts(hosts->hosts(), partial));
}

void Exporter::showInFolder(const QUrl &file) const
{
    if (!file.isLocalFile())
        return;
    const QString dir = QFileInfo(file.toLocalFile()).absolutePath();
    QDesktopServices::openUrl(QUrl::fromLocalFile(dir));
}
