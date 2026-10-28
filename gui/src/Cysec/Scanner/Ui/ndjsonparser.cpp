// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "ndjsonparser.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>

// The engine's stdout is untrusted input: every field is read defensively.
// A missing or wrong-typed field leaves the ScanEvent default in place and
// never asserts, so a buggy or hostile child cannot crash the GUI. Strings
// are kept verbatim; rendering safety is the view's job (PlainLabel).

namespace {

QString str(const QJsonObject &o, QLatin1StringView key)
{
    const QJsonValue v = o.value(key);
    return v.isString() ? v.toString() : QString();
}

int integer(const QJsonObject &o, QLatin1StringView key, int fallback)
{
    const QJsonValue v = o.value(key);
    return v.isDouble() ? v.toInt(fallback) : fallback;
}

double real(const QJsonObject &o, QLatin1StringView key, double fallback)
{
    const QJsonValue v = o.value(key);
    return v.isDouble() ? v.toDouble(fallback) : fallback;
}

bool boolean(const QJsonObject &o, QLatin1StringView key)
{
    const QJsonValue v = o.value(key);
    return v.isBool() && v.toBool();
}

QJsonObject object(const QJsonObject &o, QLatin1StringView key, bool *present = nullptr)
{
    const QJsonValue v = o.value(key);
    if (present)
        *present = v.isObject();
    return v.isObject() ? v.toObject() : QJsonObject();
}

QStringList strings(const QJsonObject &o, QLatin1StringView key)
{
    QStringList out;
    const QJsonValue v = o.value(key);
    if (!v.isArray())
        return out;
    const QJsonArray a = v.toArray();
    for (const QJsonValue &item : a) {
        if (item.isString())
            out.append(item.toString());
    }
    return out;
}

ScanEventKind kindFromString(const QString &k)
{
    struct Entry
    {
        QLatin1StringView name;
        ScanEventKind kind;
    };
    static const Entry table[] = {
        {QLatin1StringView("phase_start"), ScanEventKind::PhaseStart},
        {QLatin1StringView("phase_done"), ScanEventKind::PhaseDone},
        {QLatin1StringView("agent_start"), ScanEventKind::AgentStart},
        {QLatin1StringView("agent_done"), ScanEventKind::AgentDone},
        {QLatin1StringView("scan_start"), ScanEventKind::ScanStart},
        {QLatin1StringView("stage_progress"), ScanEventKind::StageProgress},
        {QLatin1StringView("host"), ScanEventKind::Host},
        {QLatin1StringView("log"), ScanEventKind::Log},
        {QLatin1StringView("scan_end"), ScanEventKind::ScanEnd},
    };
    for (const Entry &e : table) {
        if (k == e.name)
            return e.kind;
    }
    return ScanEventKind::Unknown;
}

void readHost(const QJsonObject &h, HostFact &out)
{
    using L = QLatin1StringView;
    out.ip = str(h, L("ip"));
    out.externalId = str(h, L("external_id"));
    out.hostname = str(h, L("hostname"));
    out.mac = str(h, L("mac"));
    out.macVendor = str(h, L("mac_vendor"));
    out.osGuess = str(h, L("os_guess"));
    out.osGuessConfidence = real(h, L("os_guess_confidence"), -1.0);

    const QJsonValue services = h.value(L("services"));
    if (!services.isArray())
        return;
    out.servicesKnown = true;
    const QJsonArray arr = services.toArray();
    for (const QJsonValue &item : arr) {
        if (!item.isObject())
            continue;
        const QJsonObject s = item.toObject();
        ServiceFact f;
        f.port = integer(s, L("port"), 0);
        f.protocol = str(s, L("protocol"));
        f.serviceName = str(s, L("service_name"));
        f.product = str(s, L("product"));
        f.version = str(s, L("service_version"));
        out.services.append(f);
    }
}

} // namespace

std::optional<ScanEvent> NdjsonParser::parseLine(QByteArrayView line)
{
    using L = QLatin1StringView;
    if (line.isEmpty())
        return std::nullopt;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(line.toByteArray(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return std::nullopt;
    const QJsonObject o = doc.object();

    ScanEvent ev;
    ev.kind = kindFromString(str(o, L("kind")));
    ev.seq = integer(o, L("seq"), -1);
    ev.ts = real(o, L("ts"), 0.0);
    ev.agent = str(o, L("agent")); // null on phase_* events -> empty

    switch (ev.kind) {
    case ScanEventKind::ScanStart: {
        const QJsonObject scan = object(o, L("scan"));
        ev.scope = strings(scan, L("scope"));
        ev.stages = strings(scan, L("stages"));
        bool hasCaps = false;
        const QJsonObject caps = object(scan, L("capabilities"), &hasCaps);
        ev.hasCapabilities = hasCaps;
        ev.capUnprivilegedIcmp = boolean(caps, L("unprivileged_icmp"));
        ev.capSystemPing = boolean(caps, L("system_ping"));
        ev.capArpCache = boolean(caps, L("arp_cache"));
        break;
    }
    case ScanEventKind::StageProgress: {
        const QJsonObject p = object(o, L("progress"));
        ev.done = integer(p, L("done"), 0);
        ev.total = integer(p, L("total"), 0);
        break;
    }
    case ScanEventKind::Host:
        readHost(object(o, L("host")), ev.host);
        break;
    case ScanEventKind::Log: {
        const QJsonObject log = object(o, L("log"));
        ev.logLevel = str(log, L("level"));
        ev.logMessage = str(log, L("message"));
        break;
    }
    case ScanEventKind::ScanEnd: {
        const QJsonObject end = object(o, L("scan_end"));
        ev.endStatus = str(end, L("status"));
        ev.endError = str(end, L("error"));
        ev.endAssets = integer(end, L("assets"), 0);
        break;
    }
    case ScanEventKind::PhaseStart:
    case ScanEventKind::PhaseDone:
    case ScanEventKind::AgentStart:
    case ScanEventKind::AgentDone:
    case ScanEventKind::Unknown:
        break;
    }
    return ev;
}

QList<QByteArray> NdjsonLineBuffer::append(const QByteArray &chunk)
{
    QList<QByteArray> lines;
    qsizetype pos = 0;
    while (pos < chunk.size()) {
        const qsizetype nl = chunk.indexOf('\n', pos);
        if (nl < 0) {
            // Partial trailing data. While discarding the rest of an
            // oversized line nothing is kept, so memory stays bounded.
            if (!m_discarding) {
                m_pending.append(chunk.constData() + pos, chunk.size() - pos);
                if (m_pending.size() > kMaxLineBytes) {
                    m_overflowed = true;
                    m_discarding = true;
                    m_pending.clear();
                    m_pending.squeeze();
                }
            }
            break;
        }

        if (m_discarding) {
            // This newline ends the oversized line; drop its tail.
            m_discarding = false;
        } else {
            m_pending.append(chunk.constData() + pos, nl - pos);
            if (m_pending.size() > kMaxLineBytes) {
                m_overflowed = true;
            } else {
                if (m_pending.endsWith('\r'))
                    m_pending.chop(1);
                if (!m_pending.trimmed().isEmpty())
                    lines.append(m_pending);
            }
        }
        m_pending.clear();
        pos = nl + 1;
    }
    return lines;
}

bool NdjsonLineBuffer::overflowed() const
{
    return m_overflowed;
}

void NdjsonLineBuffer::reset()
{
    m_pending.clear();
    m_overflowed = false;
    m_discarding = false;
}
