// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "hostmodel.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QTimer>

#include <algorithm>
#include <climits>

// Rows are keyed by IP, not external_id: discovery re-keys an asset from
// "ip:<ip>" to "mac:<mac>" after L2 enrichment, and the row must survive
// that (13-RESEARCH Pitfall 4). Live host events land in a pending map and
// are flushed at most every 100 ms so a /16 sweep cannot cause a repaint
// storm (Pitfall 14, T-13-34). The final payload is the source of truth
// (D-02): reconcileFromPayload replaces live rows with payload rows and
// only reads the JSON, never re-serialises it (T-13-36).
//
// Rows carry only observed facts. Nothing here grades a host (D-14).

namespace {

constexpr int kFlushIntervalMs = 100;

quint32 ipv4SortKey(const QString &ip)
{
    const QStringList parts = ip.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return 0;
    quint32 key = 0;
    for (const QString &part : parts) {
        bool ok = false;
        const uint octet = part.toUInt(&ok);
        if (!ok || octet > 255)
            return 0;
        key = (key << 8) | octet;
    }
    return key;
}

// A later event never blanks a non-empty field; services replace only when
// the newer fact actually reports them.
void mergeInto(HostFact &into, const HostFact &from)
{
    auto take = [](QString &dst, const QString &src) {
        if (!src.isEmpty())
            dst = src;
    };
    take(into.ip, from.ip);
    take(into.externalId, from.externalId);
    take(into.hostname, from.hostname);
    take(into.mac, from.mac);
    take(into.macVendor, from.macVendor);
    take(into.osGuess, from.osGuess);
    if (from.osGuessConfidence >= 0)
        into.osGuessConfidence = from.osGuessConfidence;
    if (from.servicesKnown) {
        into.services = from.services;
        into.servicesKnown = true;
    }
}

bool sameService(const ServiceFact &a, const ServiceFact &b)
{
    return a.port == b.port && a.protocol == b.protocol && a.serviceName == b.serviceName
        && a.product == b.product && a.version == b.version;
}

bool sameFact(const HostFact &a, const HostFact &b)
{
    if (a.ip != b.ip || a.externalId != b.externalId || a.hostname != b.hostname
        || a.mac != b.mac || a.macVendor != b.macVendor || a.osGuess != b.osGuess
        || a.osGuessConfidence != b.osGuessConfidence || a.servicesKnown != b.servicesKnown
        || a.services.size() != b.services.size()) {
        return false;
    }
    for (qsizetype i = 0; i < a.services.size(); ++i) {
        if (!sameService(a.services.at(i), b.services.at(i)))
            return false;
    }
    return true;
}

QList<ServiceFact> sortedServices(const HostFact &fact)
{
    QList<ServiceFact> services = fact.services;
    std::stable_sort(services.begin(), services.end(),
                     [](const ServiceFact &a, const ServiceFact &b) {
                         if (a.port != b.port)
                             return a.port < b.port;
                         return a.protocol < b.protocol;
                     });
    return services;
}

// "22, 80, 443 +3": the first three distinct port numbers, then the rest.
QString compactPorts(const HostFact &fact)
{
    QList<int> ports;
    for (const ServiceFact &s : sortedServices(fact)) {
        if (ports.isEmpty() || ports.last() != s.port)
            ports.append(s.port);
    }
    QStringList shown;
    for (qsizetype i = 0; i < ports.size() && i < 3; ++i)
        shown.append(QString::number(ports.at(i)));
    QString out = shown.join(QStringLiteral(", "));
    if (ports.size() > 3)
        out += QStringLiteral(" +%1").arg(ports.size() - 3);
    return out;
}

QString portsList(const HostFact &fact)
{
    QStringList out;
    for (const ServiceFact &s : sortedServices(fact)) {
        out.append(s.protocol.isEmpty()
                       ? QString::number(s.port)
                       : QStringLiteral("%1/%2").arg(s.port).arg(s.protocol));
    }
    return out.join(QLatin1Char(' '));
}

QVariantList servicesList(const HostFact &fact)
{
    QVariantList out;
    for (const ServiceFact &s : sortedServices(fact)) {
        out.append(QVariantMap{
            {QStringLiteral("port"), s.port},
            {QStringLiteral("protocol"), s.protocol},
            {QStringLiteral("serviceName"), s.serviceName},
            {QStringLiteral("product"), s.product},
            {QStringLiteral("version"), s.version},
        });
    }
    return out;
}

QVariantMap hostMap(const HostFact &fact)
{
    return {
        {QStringLiteral("ip"), fact.ip},
        {QStringLiteral("hostname"), fact.hostname},
        {QStringLiteral("mac"), fact.mac},
        {QStringLiteral("vendor"), fact.macVendor},
        {QStringLiteral("osGuess"), fact.osGuess},
        {QStringLiteral("osGuessConfidence"),
         fact.osGuessConfidence >= 0 ? QVariant(fact.osGuessConfidence) : QVariant()},
        {QStringLiteral("externalId"), fact.externalId},
        {QStringLiteral("services"), servicesList(fact)},
        {QStringLiteral("ports"), compactPorts(fact)},
        {QStringLiteral("portsList"), portsList(fact)},
        {QStringLiteral("sortKey"), ipv4SortKey(fact.ip)},
    };
}

// Nullable payload strings: anything that is not a JSON string is "unknown",
// represented as an empty QString (the UI layer renders the word).
QString str(const QJsonObject &o, QLatin1StringView key)
{
    const QJsonValue v = o.value(key);
    return v.isString() ? v.toString() : QString();
}

HostFact factFromAsset(const QJsonObject &asset)
{
    HostFact f;
    f.externalId = str(asset, QLatin1StringView("external_id"));
    f.hostname = str(asset, QLatin1StringView("hostname"));
    f.ip = str(asset, QLatin1StringView("ip_address"));
    f.mac = str(asset, QLatin1StringView("mac_address"));
    f.macVendor = str(asset, QLatin1StringView("mac_vendor"));
    f.osGuess = str(asset, QLatin1StringView("os_guess"));
    const QJsonValue conf = asset.value(QLatin1StringView("os_guess_confidence"));
    f.osGuessConfidence = conf.isDouble() ? conf.toDouble() : -1.0;
    f.servicesKnown = true;
    const QJsonArray services = asset.value(QLatin1StringView("services")).toArray();
    for (const QJsonValue &sv : services) {
        if (!sv.isObject())
            continue;
        const QJsonObject so = sv.toObject();
        ServiceFact s;
        s.port = so.value(QLatin1StringView("port")).toInt();
        s.protocol = str(so, QLatin1StringView("protocol"));
        s.serviceName = str(so, QLatin1StringView("service_name"));
        s.product = str(so, QLatin1StringView("product"));
        s.version = str(so, QLatin1StringView("service_version"));
        f.services.append(s);
    }
    return f;
}

} // namespace

HostModel::HostModel(QObject *parent)
    : QAbstractListModel(parent)
    , m_flushTimer(new QTimer(this))
{
    m_flushTimer->setSingleShot(true);
    m_flushTimer->setInterval(kFlushIntervalMs);
    connect(m_flushTimer, &QTimer::timeout, this, &HostModel::flushNow);
}

QString HostModel::keyOf(const HostFact &fact)
{
    if (!fact.ip.isEmpty())
        return fact.ip;
    if (!fact.externalId.isEmpty())
        return QStringLiteral("id:") + fact.externalId;
    return {};
}

void HostModel::rebuildIndex()
{
    m_index.clear();
    m_index.reserve(m_hosts.size());
    for (qsizetype i = 0; i < m_hosts.size(); ++i)
        m_index.insert(keyOf(m_hosts.at(i)), int(i));
}

int HostModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    return int(m_hosts.size());
}

QVariant HostModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.parent().isValid() || index.row() >= m_hosts.size())
        return {};
    const HostFact &h = m_hosts.at(index.row());
    switch (role) {
    case Qt::DisplayRole:
    case IpRole:
        return h.ip;
    case HostnameRole:
        return h.hostname;
    case VendorRole:
        return h.macVendor;
    case MacRole:
        return h.mac;
    case PortsRole:
        return compactPorts(h);
    case PortsListRole:
        return portsList(h);
    case OsGuessRole:
        return h.osGuess;
    case ExternalIdRole:
        return h.externalId;
    case ServicesRole:
        return servicesList(h);
    case SortKeyRole:
        return ipv4SortKey(h.ip);
    case HostRole:
        return hostMap(h);
    default:
        return {};
    }
}

QHash<int, QByteArray> HostModel::roleNames() const
{
    return {
        {IpRole, QByteArrayLiteral("ip")},
        {HostnameRole, QByteArrayLiteral("hostname")},
        {VendorRole, QByteArrayLiteral("vendor")},
        {MacRole, QByteArrayLiteral("mac")},
        {PortsRole, QByteArrayLiteral("ports")},
        {PortsListRole, QByteArrayLiteral("portsList")},
        {OsGuessRole, QByteArrayLiteral("osGuess")},
        {ExternalIdRole, QByteArrayLiteral("externalId")},
        {ServicesRole, QByteArrayLiteral("services")},
        {SortKeyRole, QByteArrayLiteral("sortKey")},
        {HostRole, QByteArrayLiteral("host")},
    };
}

void HostModel::upsert(const HostFact &fact)
{
    const QString key = keyOf(fact);
    if (key.isEmpty())
        return; // nothing to identify the host by
    auto it = m_pending.find(key);
    if (it != m_pending.end()) {
        mergeInto(*it, fact);
    } else {
        m_pending.insert(key, fact);
        m_pendingOrder.append(key);
    }
    // Do not restart a running timer: the first pending fact bounds latency.
    if (!m_flushTimer->isActive())
        m_flushTimer->start();
}

void HostModel::flushNow()
{
    m_flushTimer->stop();
    if (m_pending.isEmpty())
        return;

    QList<HostFact> appended;
    int firstChanged = INT_MAX;
    int lastChanged = -1;
    for (const QString &key : std::as_const(m_pendingOrder)) {
        const HostFact &incoming = m_pending.value(key);
        const auto existing = m_index.constFind(key);
        if (existing == m_index.cend()) {
            appended.append(incoming);
            continue;
        }
        const int row = existing.value();
        HostFact merged = m_hosts.at(row);
        mergeInto(merged, incoming);
        if (!sameFact(merged, m_hosts.at(row))) {
            m_hosts[row] = merged;
            firstChanged = std::min(firstChanged, row);
            lastChanged = std::max(lastChanged, row);
        }
    }
    m_pending.clear();
    m_pendingOrder.clear();

    if (lastChanged >= 0)
        emit dataChanged(index(firstChanged), index(lastChanged));

    if (!appended.isEmpty()) {
        const int first = int(m_hosts.size());
        beginInsertRows(QModelIndex(), first, first + int(appended.size()) - 1);
        for (const HostFact &f : std::as_const(appended)) {
            m_index.insert(keyOf(f), int(m_hosts.size()));
            m_hosts.append(f);
        }
        endInsertRows();
        emit countChanged();
    }
}

bool HostModel::reconcileFromPayload(const QByteArray &payloadJson)
{
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(payloadJson, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return false;
    const QJsonValue assetsValue = doc.object().value(QLatin1StringView("assets"));
    if (!assetsValue.isArray())
        return false;

    // Pending live facts are folded in first so the payload has the last word.
    flushNow();

    QList<HostFact> payloadHosts;
    QHash<QString, int> payloadIndex;
    const QJsonArray assets = assetsValue.toArray();
    for (const QJsonValue &av : assets) {
        if (!av.isObject())
            continue;
        const HostFact f = factFromAsset(av.toObject());
        const QString key = keyOf(f);
        if (key.isEmpty())
            continue;
        const auto dup = payloadIndex.constFind(key);
        if (dup != payloadIndex.cend()) {
            payloadHosts[dup.value()] = f;
        } else {
            payloadIndex.insert(key, int(payloadHosts.size()));
            payloadHosts.append(f);
        }
    }

    const int countBefore = int(m_hosts.size());
    bool changed = false;

    // 1. Remove live rows the payload does not contain, as contiguous ranges
    //    walked from the end so earlier row numbers stay valid.
    int row = int(m_hosts.size()) - 1;
    while (row >= 0) {
        if (payloadIndex.contains(keyOf(m_hosts.at(row)))) {
            --row;
            continue;
        }
        const int last = row;
        while (row - 1 >= 0 && !payloadIndex.contains(keyOf(m_hosts.at(row - 1))))
            --row;
        beginRemoveRows(QModelIndex(), row, last);
        m_hosts.remove(row, last - row + 1);
        endRemoveRows();
        changed = true;
        --row;
    }
    rebuildIndex();

    // 2. Replace surviving rows with their payload version.
    int firstChanged = INT_MAX;
    int lastChanged = -1;
    for (qsizetype i = 0; i < m_hosts.size(); ++i) {
        const HostFact &p = payloadHosts.at(payloadIndex.value(keyOf(m_hosts.at(i))));
        if (!sameFact(p, m_hosts.at(i))) {
            m_hosts[i] = p;
            firstChanged = std::min(firstChanged, int(i));
            lastChanged = std::max(lastChanged, int(i));
        }
    }
    if (lastChanged >= 0) {
        emit dataChanged(index(firstChanged), index(lastChanged));
        changed = true;
    }

    // 3. Append payload-only hosts in payload order.
    QList<HostFact> added;
    for (const HostFact &p : std::as_const(payloadHosts)) {
        if (!m_index.contains(keyOf(p)))
            added.append(p);
    }
    if (!added.isEmpty()) {
        const int first = int(m_hosts.size());
        beginInsertRows(QModelIndex(), first, first + int(added.size()) - 1);
        for (const HostFact &f : std::as_const(added)) {
            m_index.insert(keyOf(f), int(m_hosts.size()));
            m_hosts.append(f);
        }
        endInsertRows();
        changed = true;
    }

    if (int(m_hosts.size()) != countBefore)
        emit countChanged();
    return changed;
}

void HostModel::clear()
{
    m_flushTimer->stop();
    const bool hadRows = !m_hosts.isEmpty();
    beginResetModel();
    m_hosts.clear();
    m_index.clear();
    m_pending.clear();
    m_pendingOrder.clear();
    endResetModel();
    if (hadRows)
        emit countChanged();
}

int HostModel::count() const
{
    return int(m_hosts.size());
}

QVariantMap HostModel::hostAt(int row) const
{
    if (row < 0 || row >= m_hosts.size())
        return {};
    return hostMap(m_hosts.at(row));
}

QList<HostFact> HostModel::hosts() const
{
    return m_hosts;
}
