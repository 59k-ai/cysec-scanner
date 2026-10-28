// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "validators.h"

#include <QRegularExpression>
#include <QSet>

#include <algorithm>

// The grammar here mirrors the engine, not a generic notion of "valid":
//  - scope entries follow netutil.parsePrefixOrAddr, i.e. Go's
//    netip.ParsePrefix / netip.ParseAddr restricted to IPv4, then Masked().
//    netip rejects octets and prefix bits with a leading zero, signs, zones
//    and surrounding whitespace, so this parser does too.
//  - port specs follow portscan.ParsePorts + parsePort (strconv.Atoi), which
//    accepts an optional sign and leading zeros but only ASCII digits.
// Results carry enum codes only; QML maps them to translated text.

namespace {

quint32 maskFor(int prefixLen)
{
    // mask(0) == 0; shifting a 32-bit value by 32 is undefined, so special-case it.
    return prefixLen <= 0 ? 0u : (0xFFFFFFFFu << (32 - prefixLen));
}

bool isAsciiDigit(QChar c)
{
    return c >= u'0' && c <= u'9';
}

// netip decimal field: non-empty ASCII digits, no leading zero unless the
// field is exactly "0", value <= maxValue.
bool parseNetipDecimal(QStringView s, int maxValue, int *out)
{
    if (s.isEmpty() || s.size() > 3)
        return false;
    if (s.size() > 1 && s.front() == u'0')
        return false;
    int v = 0;
    for (QChar c : s) {
        if (!isAsciiDigit(c))
            return false;
        v = v * 10 + (c.unicode() - u'0');
    }
    if (v > maxValue)
        return false;
    *out = v;
    return true;
}

bool parseIpv4(QStringView s, quint32 *out)
{
    const auto parts = s.split(u'.');
    if (parts.size() != 4)
        return false;
    quint32 addr = 0;
    for (QStringView part : parts) {
        int octet = 0;
        if (!parseNetipDecimal(part, 255, &octet))
            return false;
        addr = (addr << 8) | quint32(octet);
    }
    *out = addr;
    return true;
}

// strconv.Atoi then the 1..65535 band check of portscan.parsePort.
bool parsePort(QStringView token, int *out)
{
    QStringView digits = token;
    bool negative = false;
    if (!digits.isEmpty() && (digits.front() == u'+' || digits.front() == u'-')) {
        negative = digits.front() == u'-';
        digits = digits.mid(1);
    }
    if (digits.isEmpty())
        return false;
    qint64 v = 0;
    for (QChar c : digits) {
        if (!isAsciiDigit(c))
            return false;
        v = v * 10 + (c.unicode() - u'0');
        if (v > 65535) {
            // Keep scanning so a non-digit still reports as syntax, but the
            // value is already out of band either way.
            v = 65536;
        }
    }
    if (negative)
        v = -v;
    if (v < 1 || v > 65535)
        return false;
    *out = int(v);
    return true;
}

QStringList splitEntries(const QString &text)
{
    static const QRegularExpression sep(QStringLiteral("[,\\s]+"));
    return text.split(sep, Qt::SkipEmptyParts);
}

} // namespace

QString Ipv4Prefix::toString() const
{
    return QStringLiteral("%1.%2.%3.%4/%5")
        .arg((addr >> 24) & 0xFF)
        .arg((addr >> 16) & 0xFF)
        .arg((addr >> 8) & 0xFF)
        .arg(addr & 0xFF)
        .arg(prefixLen);
}

Validators::Validators(QObject *parent)
    : QObject(parent)
{
}

std::optional<Ipv4Prefix> Validators::parseScopeEntry(QStringView entry)
{
    // IPv6 (including v4-mapped ::ffff:a.b.c.d) is rejected by the engine.
    if (entry.contains(u':'))
        return std::nullopt;

    QStringView addrPart = entry;
    int prefixLen = 32;
    const qsizetype slash = entry.indexOf(u'/');
    if (slash >= 0) {
        addrPart = entry.left(slash);
        if (!parseNetipDecimal(entry.mid(slash + 1), 32, &prefixLen))
            return std::nullopt;
    }

    quint32 addr = 0;
    if (!parseIpv4(addrPart, &addr))
        return std::nullopt;

    Ipv4Prefix p;
    p.prefixLen = prefixLen;
    p.addr = addr & maskFor(prefixLen);
    return p;
}

bool Validators::parsePortSpec(QStringView spec, QList<int> *out)
{
    const QStringView trimmed = spec.trimmed();
    if (trimmed.isEmpty())
        return false;

    QSet<int> seen;
    for (QStringView raw : trimmed.split(u',')) {
        const QStringView token = raw.trimmed();
        if (token.isEmpty())
            return false;
        // strings.Cut splits on the first '-' only.
        const qsizetype dash = token.indexOf(u'-');
        if (dash >= 0) {
            int lo = 0;
            int hi = 0;
            if (!parsePort(token.left(dash).trimmed(), &lo))
                return false;
            if (!parsePort(token.mid(dash + 1).trimmed(), &hi))
                return false;
            if (lo > hi)
                return false;
            for (int p = lo; p <= hi; ++p)
                seen.insert(p);
            continue;
        }
        int p = 0;
        if (!parsePort(token, &p))
            return false;
        seen.insert(p);
    }

    if (out) {
        QList<int> ports(seen.cbegin(), seen.cend());
        std::sort(ports.begin(), ports.end());
        *out = ports;
    }
    return true;
}

bool Validators::contains(const Ipv4Prefix &outer, const Ipv4Prefix &inner)
{
    if (inner.prefixLen < outer.prefixLen)
        return false;
    const quint32 mask = maskFor(outer.prefixLen);
    return (inner.addr & mask) == (outer.addr & mask);
}

QVariantMap Validators::validateTargets(const QString &text) const
{
    const QStringList entries = splitEntries(text);
    if (entries.isEmpty())
        return {{QStringLiteral("ok"), false}, {QStringLiteral("error"), int(Empty)}};

    QStringList cidrs;
    for (const QString &entry : entries) {
        const auto p = parseScopeEntry(entry);
        if (!p) {
            return {{QStringLiteral("ok"), false},
                    {QStringLiteral("error"), int(InvalidTarget)},
                    {QStringLiteral("entry"), entry}};
        }
        const QString normalised = p->toString();
        if (!cidrs.contains(normalised))
            cidrs.append(normalised);
    }
    return {{QStringLiteral("ok"), true},
            {QStringLiteral("error"), int(Ok)},
            {QStringLiteral("cidrs"), cidrs}};
}

QVariantMap Validators::validatePorts(const QString &text) const
{
    // An empty field means "engine default set": the caller omits --ports.
    // The engine itself rejects a whitespace-only --ports, so the trimmed
    // spec (empty here) is what must be passed on.
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return {{QStringLiteral("ok"), true},
                {QStringLiteral("error"), int(Ok)},
                {QStringLiteral("ports"), QString()}};
    }
    if (!parsePortSpec(trimmed, nullptr))
        return {{QStringLiteral("ok"), false}, {QStringLiteral("error"), int(InvalidPorts)}};
    return {{QStringLiteral("ok"), true},
            {QStringLiteral("error"), int(Ok)},
            {QStringLiteral("ports"), trimmed}};
}

bool Validators::requiresAuthorisation(const QStringList &cidrs, const QStringList &localCidrs) const
{
    QList<Ipv4Prefix> locals;
    for (const QString &l : localCidrs) {
        if (const auto p = parseScopeEntry(QStringView(l).trimmed()))
            locals.append(*p);
    }

    for (const QString &c : cidrs) {
        const auto p = parseScopeEntry(QStringView(c).trimmed());
        // Anything we cannot parse cannot be shown to be local: gate it.
        if (!p)
            return true;
        const bool local = std::any_of(locals.cbegin(), locals.cend(),
                                       [&](const Ipv4Prefix &l) { return contains(l, *p); });
        if (!local)
            return true;
    }
    return false;
}
