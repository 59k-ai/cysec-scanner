// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "engineinfo.h"

#include "processscanbackend.h"
#include "validators.h"

#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QProcess>
#include <QTimer>
#include <QVariantMap>
#include <QtGlobal>

// Client for `cysec-scanner --describe` (RESEARCH E4). The answer drives the
// auth gate (local networks), the capability banner before the first scan
// (D-21), the default port hint and the engine version shown in About
// (D-23), so decoding is strict: any key of the wrong type rejects the whole
// answer and the previous facts stay in place. Each network CIDR is
// re-validated with the same parser the setup bar uses; an invalid one is
// dropped, which keeps the auth gate on for it (T-13-47).

namespace {

// A hung or chatty engine must not stall or flood the GUI (T-13-48).
constexpr int kDescribeTimeoutMs = 5000;
constexpr qsizetype kMaxDescribeBytes = 256 * 1024;

bool readStringArray(const QJsonValue &v, QStringList *out)
{
    if (!v.isArray())
        return false;
    const QJsonArray arr = v.toArray();
    for (const QJsonValue &e : arr) {
        if (!e.isString())
            return false;
        out->append(e.toString());
    }
    return true;
}

bool readPorts(const QJsonValue &v, QList<int> *out)
{
    if (!v.isArray())
        return false;
    const QJsonArray arr = v.toArray();
    for (const QJsonValue &e : arr) {
        if (!e.isDouble())
            return false;
        const double d = e.toDouble();
        const int port = int(d);
        if (double(port) != d || port < 1 || port > 65535)
            return false;
        out->append(port);
    }
    return true;
}

// Missing capability keys mean "not available"; a present key must be bool.
bool readCapability(const QJsonObject &caps, const char *key, bool *out)
{
    const QJsonValue v = caps.value(QLatin1String(key));
    if (v.isUndefined()) {
        *out = false;
        return true;
    }
    if (!v.isBool())
        return false;
    *out = v.toBool();
    return true;
}

} // namespace

EngineInfo::EngineInfo(QObject *parent)
    : QObject(parent)
{
}

bool EngineInfo::loaded() const
{
    return m_loaded;
}

bool EngineInfo::failed() const
{
    return m_failed;
}

QString EngineInfo::engineVersion() const
{
    return m_engineVersion;
}

bool EngineInfo::unprivilegedIcmp() const
{
    return m_unprivilegedIcmp;
}

bool EngineInfo::systemPing() const
{
    return m_systemPing;
}

bool EngineInfo::arpCache() const
{
    return m_arpCache;
}

QVariantList EngineInfo::networks() const
{
    return m_networks;
}

QList<int> EngineInfo::defaultPorts() const
{
    return m_defaultPorts;
}

QStringList EngineInfo::timingTiers() const
{
    return m_timingTiers;
}

QStringList EngineInfo::localCidrs() const
{
    return m_localCidrs;
}

QString EngineInfo::guiVersion() const
{
    return QStringLiteral(CYSEC_SCANNER_GUI_VERSION);
}

QString EngineInfo::qtVersion() const
{
    return QString::fromLatin1(qVersion());
}

void EngineInfo::markFailed()
{
    m_loaded = false;
    m_failed = true;
    emit changed();
}

bool EngineInfo::loadFromJson(const QByteArray &describeJson)
{
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(describeJson, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        markFailed();
        return false;
    }
    const QJsonObject root = doc.object();

    // Decode into locals; nothing is committed unless every key is valid.
    const QJsonValue version = root.value(QLatin1String("engine_version"));
    const QJsonValue capsValue = root.value(QLatin1String("capabilities"));
    const QJsonValue networksValue = root.value(QLatin1String("networks"));
    if (!version.isString() || !capsValue.isObject() || !networksValue.isArray()) {
        markFailed();
        return false;
    }

    const QJsonObject caps = capsValue.toObject();
    bool icmp = false;
    bool ping = false;
    bool arp = false;
    if (!readCapability(caps, "unprivileged_icmp", &icmp)
        || !readCapability(caps, "system_ping", &ping)
        || !readCapability(caps, "arp_cache", &arp)) {
        markFailed();
        return false;
    }

    QVariantList networks;
    QStringList cidrs;
    const QJsonArray netArray = networksValue.toArray();
    for (const QJsonValue &n : netArray) {
        if (!n.isObject()) {
            markFailed();
            return false;
        }
        const QJsonObject o = n.toObject();
        const QJsonValue iface = o.value(QLatin1String("interface"));
        const QJsonValue cidr = o.value(QLatin1String("cidr"));
        if (!iface.isString() || !cidr.isString()) {
            markFailed();
            return false;
        }
        const auto prefix = Validators::parseScopeEntry(cidr.toString());
        if (!prefix)
            continue; // dropped: the auth gate stays on for it
        const QString normalised = prefix->toString();
        networks.append(QVariantMap{{QStringLiteral("interface"), iface.toString()},
                                    {QStringLiteral("cidr"), normalised}});
        if (!cidrs.contains(normalised))
            cidrs.append(normalised);
    }

    QList<int> ports;
    QStringList tiers;
    if (!readPorts(root.value(QLatin1String("default_ports")), &ports)
        || !readStringArray(root.value(QLatin1String("timing_tiers")), &tiers)) {
        markFailed();
        return false;
    }

    m_engineVersion = version.toString();
    m_unprivilegedIcmp = icmp;
    m_systemPing = ping;
    m_arpCache = arp;
    m_networks = networks;
    m_localCidrs = cidrs;
    m_defaultPorts = ports;
    m_timingTiers = tiers;
    m_loaded = true;
    m_failed = false;
    emit changed();
    return true;
}

void EngineInfo::setEnginePath(const QString &p)
{
    m_enginePath = p;
}

void EngineInfo::refresh()
{
    if (m_process)
        return; // one describe at a time; the running one will report

    // Same resolution as the scan backend: explicit path, else the
    // CYSEC_SCANNER_BIN override or the binary next to the GUI (T-13-50).
    const QString engine = m_enginePath.isEmpty() ? ProcessScanBackend::resolveEnginePath()
                                                  : m_enginePath;
    const QFileInfo fi(engine);
    if (engine.isEmpty() || !fi.isFile() || !fi.isExecutable()) {
        markFailed();
        return;
    }

    m_stdout.clear();
    m_overflow = false;
    m_timedOut = false;

    auto *proc = new QProcess(this);
    m_process = proc;
    proc->setProgram(fi.absoluteFilePath());
    proc->setArguments({QStringLiteral("--describe")}); // no shell
    proc->setProcessChannelMode(QProcess::SeparateChannels);

    connect(proc, &QProcess::readyReadStandardOutput, this, [this, proc] {
        const QByteArray chunk = proc->readAllStandardOutput();
        if (m_overflow)
            return;
        if (m_stdout.size() + chunk.size() > kMaxDescribeBytes) {
            m_overflow = true;
            m_stdout.clear();
            proc->kill();
            return;
        }
        m_stdout += chunk;
    });
    // Diagnostics are not shown here; drain them so the pipe never fills.
    connect(proc, &QProcess::readyReadStandardError, this,
            [proc] { proc->readAllStandardError(); });
    connect(proc, &QProcess::errorOccurred, this, [this, proc](QProcess::ProcessError e) {
        // A crash (including our own kill) is reported by finished().
        if (e == QProcess::FailedToStart && m_process == proc)
            finishProcess(false);
    });
    connect(proc, &QProcess::finished, this,
            [this, proc](int exitCode, QProcess::ExitStatus status) {
                if (m_process != proc)
                    return;
                m_stdout += proc->readAllStandardOutput();
                const bool ok = !m_overflow && !m_timedOut && status == QProcess::NormalExit
                    && exitCode == 0 && m_stdout.size() <= kMaxDescribeBytes;
                finishProcess(ok);
            });

    auto *timer = new QTimer(proc);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, proc, [this, proc] {
        m_timedOut = true;
        proc->kill();
    });
    timer->start(kDescribeTimeoutMs);

    proc->start();
}

void EngineInfo::finishProcess(bool ok)
{
    QProcess *proc = m_process;
    m_process = nullptr;
    if (proc) {
        proc->disconnect(this);
        proc->deleteLater();
    }
    const QByteArray out = m_stdout;
    m_stdout.clear();
    if (ok)
        loadFromJson(out);
    else
        markFailed();
}
