// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// IpcChannel and the local IPC connectors against a scripted in-test
// QLocalServer speaking wire contract v1: hello-first authentication with a
// token re-read on every connect, call correlation, notifications, closing
// notices, reconnect with backoff, hostile server lines, server identity
// checks before any write, and filesystem-only addresses.

#include "ipcchannel.h"
#include "ipcconnect.h"
#include "ipcendpoint.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QRandomGenerator>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

#include <memory>
#include <vector>

#ifndef Q_OS_WIN
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

constexpr int kWait = 3000;

struct Peer
{
    QLocalSocket *socket = nullptr;
    QByteArray pending;
    QList<QByteArray> lines;
    qint64 bytesRead = 0;
};

// Accepts every connection and records what each client wrote, one line at a
// time. Replies are scripted by the test slots.
class ScriptedServer
{
public:
    bool listen(const QString &address)
    {
        QObject::connect(&m_server, &QLocalServer::newConnection, &m_server, [this] {
            while (QLocalSocket *s = m_server.nextPendingConnection()) {
                auto peer = std::make_unique<Peer>();
                peer->socket = s;
                Peer *raw = peer.get();
                QObject::connect(s, &QLocalSocket::readyRead, s, [raw] { drain(raw); });
                m_peers.push_back(std::move(peer));
                drain(raw);
            }
        });
        QLocalServer::removeServer(address);
        return m_server.listen(address);
    }

    qsizetype peerCount() const { return qsizetype(m_peers.size()); }
    Peer *peer(qsizetype i) const { return i < peerCount() ? m_peers[size_t(i)].get() : nullptr; }

    static void send(Peer *p, const QJsonObject &o)
    {
        sendRaw(p, QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n');
    }

    static void sendRaw(Peer *p, const QByteArray &bytes)
    {
        p->socket->write(bytes);
        p->socket->flush();
    }

private:
    static void drain(Peer *p)
    {
        const QByteArray chunk = p->socket->readAll();
        p->bytesRead += chunk.size();
        p->pending += chunk;
        qsizetype nl;
        while ((nl = p->pending.indexOf('\n')) >= 0) {
            p->lines.append(p->pending.left(nl));
            p->pending.remove(0, nl + 1);
        }
    }

    QLocalServer m_server;
    std::vector<std::unique_ptr<Peer>> m_peers;
};

QJsonObject lineObject(const Peer *p, qsizetype i)
{
    return QJsonDocument::fromJson(p->lines.value(i)).object();
}

QJsonObject response(qint64 id, const QJsonObject &result)
{
    return QJsonObject{{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
}

QJsonObject errorResponse(qint64 id, int code, const QString &message,
                          const QJsonObject &data = {})
{
    QJsonObject err{{"code", code}, {"message", message}};
    if (!data.isEmpty())
        err.insert("data", data);
    return QJsonObject{{"jsonrpc", "2.0"}, {"id", id}, {"error", err}};
}

QJsonObject notificationObject(const QString &method, const QJsonObject &params)
{
    return QJsonObject{{"jsonrpc", "2.0"}, {"method", method}, {"params", params}};
}

QJsonObject helloOk()
{
    return QJsonObject{{"protocol", 1},
                       {"server", QJsonObject{{"name", "test-host"}, {"version", "0.0.1"}}},
                       {"methods", QJsonArray{"status.get", "run.start", "events.subscribe"}}};
}

} // namespace

class TstIpcClient : public QObject
{
    Q_OBJECT

private slots:
    void init();
    void cleanup();

    void helloCarriesTokenFromFile();
    void tokenReReadOnReconnect();
    void unauthenticatedMapsToNotAuthorized();
    void protocolMismatchStopsRetrying();
    void callCorrelation();
    void notificationsDelivered();
    void closingNotice();
    void hostileServerLines();
    void serverNotTrustedRefusesBeforeWrite();
    void invalidAddressRefused_data();
    void invalidAddressRefused();
    void tokenFilePermissions();
    void tokenReaderRules();
    void windowsConnectorSourceRules();

private:
    bool writeToken(const QByteArray &token, int mode = 0600);
    IpcEndpoint endpoint(IpcServerPolicy policy = IpcServerPolicy::sameUser()) const;
    // Waits for connection `index`, checks it opened with a hello and
    // answers it; returns the peer once the channel is Ready.
    Peer *handshake(IpcChannel &channel, qsizetype index);

    std::unique_ptr<QTemporaryDir> m_sockDir;
    std::unique_ptr<QTemporaryDir> m_tokenDir;
    std::unique_ptr<ScriptedServer> m_server;
    QString m_address;
    QString m_tokenPath;
};

void TstIpcClient::init()
{
#ifdef Q_OS_WIN
    m_sockDir.reset();
    m_address = QStringLiteral("\\\\.\\pipe\\scanner-ipc-test-%1")
                    .arg(QRandomGenerator::global()->generate64(), 0, 16);
#else
    // A short base keeps the socket path inside sun_path on every OS.
    m_sockDir = std::make_unique<QTemporaryDir>(QStringLiteral("/tmp/ipct-XXXXXX"));
    QVERIFY(m_sockDir->isValid());
    m_address = m_sockDir->filePath(QStringLiteral("s"));
#endif
    m_tokenDir = std::make_unique<QTemporaryDir>();
    QVERIFY(m_tokenDir->isValid());
    m_tokenPath = m_tokenDir->filePath(QStringLiteral("token"));
    QVERIFY(writeToken("tok-A"));
    m_server = std::make_unique<ScriptedServer>();
    QVERIFY(m_server->listen(m_address));
}

void TstIpcClient::cleanup()
{
    m_server.reset();
    m_sockDir.reset();
    m_tokenDir.reset();
}

bool TstIpcClient::writeToken(const QByteArray &token, int mode)
{
    QFile f(m_tokenPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    f.write(token);
    f.close();
#ifndef Q_OS_WIN
    if (::chmod(QFile::encodeName(m_tokenPath).constData(), mode_t(mode)) != 0)
        return false;
#else
    Q_UNUSED(mode);
#endif
    return true;
}

IpcEndpoint TstIpcClient::endpoint(IpcServerPolicy policy) const
{
    IpcEndpoint e;
    e.address = m_address;
    e.tokenFile = m_tokenPath;
    e.policy = std::move(policy);
    e.clientName = QStringLiteral("test-gui");
    e.clientVersion = QStringLiteral("9.8.7");
    return e;
}

Peer *TstIpcClient::handshake(IpcChannel &channel, qsizetype index)
{
    Peer *p = nullptr;
    [&] {
        QTRY_VERIFY_WITH_TIMEOUT(m_server->peerCount() > index, kWait);
        p = m_server->peer(index);
        QTRY_VERIFY_WITH_TIMEOUT(!p->lines.isEmpty(), kWait);
        const QJsonObject hello = lineObject(p, 0);
        QCOMPARE(hello.value("method").toString(), QStringLiteral("session.hello"));
        ScriptedServer::send(p, response(hello.value("id").toInteger(), helloOk()));
        QTRY_COMPARE_WITH_TIMEOUT(channel.state(), IpcChannel::Ready, kWait);
    }();
    return QTest::currentTestFailed() ? nullptr : p;
}

void TstIpcClient::helloCarriesTokenFromFile()
{
    IpcChannel channel(endpoint());
    QSignalSpy ready(&channel, &IpcChannel::ready);
    channel.open();

    QTRY_COMPARE_WITH_TIMEOUT(m_server->peerCount(), qsizetype(1), kWait);
    Peer *p = m_server->peer(0);
    QTRY_VERIFY_WITH_TIMEOUT(!p->lines.isEmpty(), kWait);
    QCOMPARE(channel.state(), IpcChannel::Authenticating);

    const QJsonObject hello = lineObject(p, 0);
    QCOMPARE(hello.value("jsonrpc").toString(), QStringLiteral("2.0"));
    QCOMPARE(hello.value("method").toString(), QStringLiteral("session.hello"));
    QVERIFY(hello.value("id").isDouble());
    const QJsonObject params = hello.value("params").toObject();
    QCOMPARE(params.value("protocol").toInt(), 1);
    QCOMPARE(params.value("token").toString(), QStringLiteral("tok-A"));
    const QJsonObject client = params.value("client").toObject();
    QCOMPARE(client.value("name").toString(), QStringLiteral("test-gui"));
    QCOMPARE(client.value("version").toString(), QStringLiteral("9.8.7"));

    ScriptedServer::send(p, response(hello.value("id").toInteger(), helloOk()));
    QTRY_COMPARE_WITH_TIMEOUT(channel.state(), IpcChannel::Ready, kWait);
    QCOMPARE(ready.count(), 1);
    QCOMPARE(channel.lastFailure(), IpcChannel::NoFailure);
    QCOMPARE(channel.helloResult().value("methods").toArray(),
             (QJsonArray{"status.get", "run.start", "events.subscribe"}));
}

void TstIpcClient::tokenReReadOnReconnect()
{
    IpcChannel channel(endpoint());
    channel.setBackoff(20, 80);
    channel.open();
    Peer *first = handshake(channel, 0);
    QVERIFY(first);
    QCOMPARE(lineObject(first, 0).value("params").toObject().value("token").toString(),
             QStringLiteral("tok-A"));

    QVERIFY(writeToken("tok-B"));
    first->socket->disconnectFromServer();

    Peer *second = handshake(channel, 1);
    QVERIFY(second);
    QCOMPARE(lineObject(second, 0).value("params").toObject().value("token").toString(),
             QStringLiteral("tok-B"));
}

void TstIpcClient::unauthenticatedMapsToNotAuthorized()
{
    IpcChannel channel(endpoint());
    channel.setBackoff(20, 80);
    QList<IpcChannel::State> stateAtFailure;
    QObject::connect(&channel, &IpcChannel::failure, &channel,
                     [&](IpcChannel::Failure) { stateAtFailure.append(channel.state()); });
    QSignalSpy failures(&channel, &IpcChannel::failure);
    channel.open();

    QTRY_COMPARE_WITH_TIMEOUT(m_server->peerCount(), qsizetype(1), kWait);
    Peer *p = m_server->peer(0);
    QTRY_VERIFY_WITH_TIMEOUT(!p->lines.isEmpty(), kWait);
    ScriptedServer::send(p, errorResponse(lineObject(p, 0).value("id").toInteger(), -32001,
                                          QStringLiteral("unauthenticated")));

    QTRY_COMPARE_WITH_TIMEOUT(failures.count(), 1, kWait);
    QCOMPARE(failures.at(0).at(0).value<IpcChannel::Failure>(), IpcChannel::NotAuthorized);
    QCOMPARE(stateAtFailure.value(0), IpcChannel::Backoff);
    QCOMPARE(channel.lastFailure(), IpcChannel::NotAuthorized);

    // The channel retries after the backoff and authenticates again.
    QVERIFY(handshake(channel, 1));
    QCOMPARE(channel.lastFailure(), IpcChannel::NoFailure);
}

void TstIpcClient::protocolMismatchStopsRetrying()
{
    IpcChannel channel(endpoint());
    channel.setBackoff(20, 80);
    QSignalSpy failures(&channel, &IpcChannel::failure);
    channel.open();

    QTRY_COMPARE_WITH_TIMEOUT(m_server->peerCount(), qsizetype(1), kWait);
    Peer *p = m_server->peer(0);
    QTRY_VERIFY_WITH_TIMEOUT(!p->lines.isEmpty(), kWait);
    ScriptedServer::send(p, errorResponse(lineObject(p, 0).value("id").toInteger(), -32005,
                                          QStringLiteral("unsupported protocol"),
                                          QJsonObject{{"min", 1}, {"max", 1}}));

    QTRY_COMPARE_WITH_TIMEOUT(failures.count(), 1, kWait);
    QCOMPARE(failures.at(0).at(0).value<IpcChannel::Failure>(), IpcChannel::ProtocolMismatch);
    QCOMPARE(channel.state(), IpcChannel::Disconnected);
    QTest::qWait(500);
    QCOMPARE(m_server->peerCount(), qsizetype(1));
    QCOMPARE(failures.count(), 1);
    QCOMPARE(channel.state(), IpcChannel::Disconnected);
}

void TstIpcClient::callCorrelation()
{
    IpcChannel idle(endpoint());
    QSignalSpy idleReplies(&idle, &IpcChannel::replied);
    QCOMPARE(idle.call(QStringLiteral("status.get"), {}), qint64(-1));
    QCOMPARE(idleReplies.count(), 0);

    IpcChannel channel(endpoint());
    channel.open();
    Peer *p = handshake(channel, 0);
    QVERIFY(p);

    QSignalSpy replies(&channel, &IpcChannel::replied);
    QSignalSpy errors(&channel, &IpcChannel::callFailed);
    const qint64 a = channel.call(QStringLiteral("status.get"), {});
    const qint64 b = channel.call(QStringLiteral("last_run.get"), {});
    QVERIFY(a > 0);
    QVERIFY(b > 0);
    QVERIFY(a != b);

    QTRY_COMPARE_WITH_TIMEOUT(p->lines.size(), qsizetype(3), kWait);
    QCOMPARE(lineObject(p, 1).value("method").toString(), QStringLiteral("status.get"));
    QCOMPARE(lineObject(p, 1).value("id").toInteger(), a);
    QCOMPARE(lineObject(p, 1).value("jsonrpc").toString(), QStringLiteral("2.0"));
    QCOMPARE(lineObject(p, 2).value("method").toString(), QStringLiteral("last_run.get"));
    QCOMPARE(lineObject(p, 2).value("id").toInteger(), b);

    // Out of order, plus one reply for an id nobody asked for (ignored).
    ScriptedServer::send(p, response(b, QJsonObject{{"summary", QJsonValue::Null}}));
    ScriptedServer::send(p, response(9999, QJsonObject{{"x", 1}}));
    ScriptedServer::send(p, response(a, QJsonObject{{"state", "idle"}}));
    QTRY_COMPARE_WITH_TIMEOUT(replies.count(), 2, kWait);
    QCOMPARE(replies.at(0).at(0).toLongLong(), b);
    QCOMPARE(replies.at(1).at(0).toLongLong(), a);
    QCOMPARE(replies.at(1).at(1).toJsonObject().value("state").toString(), QStringLiteral("idle"));

    const qint64 c = channel.call(QStringLiteral("run.start"), {});
    QTRY_COMPARE_WITH_TIMEOUT(p->lines.size(), qsizetype(4), kWait);
    ScriptedServer::send(p, errorResponse(c, -32002, QStringLiteral("run already in progress"),
                                          QJsonObject{{"run_id", "r-1"}}));
    QTRY_COMPARE_WITH_TIMEOUT(errors.count(), 1, kWait);
    QCOMPARE(errors.at(0).at(0).toLongLong(), c);
    QCOMPARE(errors.at(0).at(1).toInt(), -32002);
    QCOMPARE(errors.at(0).at(2).toString(), QStringLiteral("run already in progress"));
    QCOMPARE(errors.at(0).at(3).toJsonObject().value("run_id").toString(), QStringLiteral("r-1"));
    QCOMPARE(replies.count(), 2);
    QCOMPARE(channel.state(), IpcChannel::Ready);

    // close() fails whatever is still in flight.
    const qint64 d = channel.call(QStringLiteral("status.get"), {});
    QVERIFY(d > 0);
    channel.close();
    QCOMPARE(errors.count(), 2);
    QCOMPARE(errors.at(1).at(0).toLongLong(), d);
    QCOMPARE(errors.at(1).at(1).toInt(), -32011);
    QCOMPARE(channel.state(), IpcChannel::Disconnected);
}

void TstIpcClient::notificationsDelivered()
{
    IpcChannel channel(endpoint());
    channel.open();
    Peer *p = handshake(channel, 0);
    QVERIFY(p);

    QSignalSpy notes(&channel, &IpcChannel::notification);
    const QJsonObject event{{"kind", "stage_progress"}, {"seq", 41}, {"agent", "port"},
                            {"progress", QJsonObject{{"done", 120}, {"total", 256}}}};
    ScriptedServer::send(p, notificationObject(
                                QStringLiteral("progress"),
                                QJsonObject{{"run_id", "r-1"}, {"replay", false}, {"event", event}}));
    ScriptedServer::send(p, notificationObject(
                                QStringLiteral("run.state"),
                                QJsonObject{{"run_id", "r-1"}, {"state", "ended"},
                                            {"outcome", "cancelled"}}));
    ScriptedServer::send(p, notificationObject(QStringLiteral("snapshot.done"),
                                               QJsonObject{{"run_id", "r-1"}, {"last_seq", 41}}));

    QTRY_COMPARE_WITH_TIMEOUT(notes.count(), 3, kWait);
    QCOMPARE(notes.at(0).at(0).toString(), QStringLiteral("progress"));
    QCOMPARE(notes.at(0).at(1).toJsonObject().value("event").toObject(), event);
    QCOMPARE(notes.at(1).at(0).toString(), QStringLiteral("run.state"));
    QCOMPARE(notes.at(1).at(1).toJsonObject().value("outcome").toString(),
             QStringLiteral("cancelled"));
    QCOMPARE(notes.at(2).at(0).toString(), QStringLiteral("snapshot.done"));
    QCOMPARE(notes.at(2).at(1).toJsonObject().value("last_seq").toInt(), 41);
    QCOMPARE(channel.state(), IpcChannel::Ready);
}

void TstIpcClient::closingNotice()
{
    IpcChannel channel(endpoint());
    channel.setBackoff(20, 80);
    channel.open();
    Peer *p = handshake(channel, 0);
    QVERIFY(p);

    QSignalSpy closing(&channel, &IpcChannel::closing);
    ScriptedServer::send(p, notificationObject(
                                QStringLiteral("session.closing"),
                                QJsonObject{{"code", -32010}, {"reason", "slow_consumer"}}));
    QTRY_COMPARE_WITH_TIMEOUT(closing.count(), 1, kWait);
    QCOMPARE(closing.at(0).at(0).toInt(), -32010);
    QCOMPARE(closing.at(0).at(1).toString(), QStringLiteral("slow_consumer"));

    QVERIFY(handshake(channel, 1));
}

void TstIpcClient::hostileServerLines()
{
    IpcChannel channel(endpoint());
    channel.setBackoff(20, 80);
    QSignalSpy failures(&channel, &IpcChannel::failure);
    channel.open();

    const QList<QByteArray> hostile = {
        QByteArray("this is not json\n"),
        QByteArray("[1,2,3]\n"),
        QByteArray("{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n"),
        QByteArray(2 << 20, 'x') + '\n',
        QByteArray("{\"id\":1,\"result\":{}}\n"),
        QByteArray("{\"jsonrpc\":\"2.0\",\"method\":\"progress\",\"params\":[1]}\n"),
    };
    for (qsizetype i = 0; i < hostile.size(); ++i) {
        Peer *p = handshake(channel, i);
        QVERIFY2(p, qPrintable(QStringLiteral("handshake %1").arg(i)));
        ScriptedServer::sendRaw(p, hostile[i]);
        QTRY_COMPARE_WITH_TIMEOUT(failures.count(), int(i + 1), kWait);
        QCOMPARE(failures.last().at(0).value<IpcChannel::Failure>(), IpcChannel::ProtocolError);
    }
    // Still alive and reconnecting after every hostile line.
    QVERIFY(handshake(channel, hostile.size()));
}

void TstIpcClient::serverNotTrustedRefusesBeforeWrite()
{
    IpcServerIdentity seen;
    int asked = 0;
    IpcChannel channel(endpoint(IpcServerPolicy::custom([&](const IpcServerIdentity &id) {
        seen = id;
        ++asked;
        return false;
    })));
    channel.setBackoff(1000, 1000);
    QSignalSpy failures(&channel, &IpcChannel::failure);
    channel.open();

    QTRY_VERIFY_WITH_TIMEOUT(failures.count() >= 1, kWait);
    QCOMPARE(failures.at(0).at(0).value<IpcChannel::Failure>(), IpcChannel::ServerNotTrusted);
    QCOMPARE(channel.lastFailure(), IpcChannel::ServerNotTrusted);
    QCOMPARE(asked, 1);
    QCOMPARE(seen.pid, QCoreApplication::applicationPid());
#ifndef Q_OS_WIN
    QCOMPARE(seen.uid, qint64(::geteuid()));
#else
    QVERIFY(!seen.sid.isEmpty());
#endif

    QTRY_VERIFY_WITH_TIMEOUT(m_server->peerCount() >= 1, kWait);
    QTest::qWait(200);
    for (qsizetype i = 0; i < m_server->peerCount(); ++i)
        QCOMPARE(m_server->peer(i)->bytesRead, qint64(0));
    channel.close();
}

void TstIpcClient::invalidAddressRefused_data()
{
    QTest::addColumn<QString>("address");
    QTest::newRow("relative") << QStringLiteral("run/ipc.sock");
    QTest::newRow("abstract") << QStringLiteral("@name");
    QTest::newRow("empty") << QString();
    QTest::newRow("too-long") << (QStringLiteral("/") + QString(150, QLatin1Char('a')));
    QTest::newRow("nested-pipe") << QStringLiteral("\\\\.\\pipe\\a\\b");
    QTest::newRow("bare-pipe-prefix") << QStringLiteral("\\\\.\\pipe\\");
}

void TstIpcClient::invalidAddressRefused()
{
    QFETCH(QString, address);
    QVERIFY(!ipcAddressIsValid(address));
    QVERIFY(ipcAddressIsValid(m_address));

    IpcEndpoint e = endpoint();
    e.address = address;
    IpcChannel channel(e);
    channel.setBackoff(20, 80);
    QSignalSpy failures(&channel, &IpcChannel::failure);
    channel.open();
    QCOMPARE(failures.count(), 1);
    QCOMPARE(failures.at(0).at(0).value<IpcChannel::Failure>(), IpcChannel::ServiceUnavailable);
    QCOMPARE(channel.state(), IpcChannel::Disconnected);

    QLocalSocket socket;
    QCOMPARE(ipcConnect(&socket, e, 100), IpcConnectError::InvalidAddress);
    QCOMPARE(socket.state(), QLocalSocket::UnconnectedState);

    QTest::qWait(100);
    QCOMPARE(failures.count(), 1);
    QCOMPARE(m_server->peerCount(), qsizetype(0));
}

void TstIpcClient::tokenFilePermissions()
{
#ifdef Q_OS_WIN
    QSKIP("token file mode bits are a Unix check");
#else
    for (int mode : {0620, 0602, 0666}) {
        QVERIFY(writeToken("tok-A", mode));
        IpcChannel channel(endpoint());
        channel.setBackoff(1000, 1000);
        QSignalSpy failures(&channel, &IpcChannel::failure);
        channel.open();
        QCOMPARE(failures.count(), 1);
        QCOMPARE(failures.at(0).at(0).value<IpcChannel::Failure>(), IpcChannel::NotAuthorized);
        channel.close();
    }
    QTest::qWait(100);
    QCOMPARE(m_server->peerCount(), qsizetype(0));

    QVERIFY(QFile::remove(m_tokenPath));
    IpcChannel missing(endpoint());
    missing.setBackoff(1000, 1000);
    QSignalSpy failures(&missing, &IpcChannel::failure);
    missing.open();
    QCOMPARE(failures.count(), 1);
    QCOMPARE(failures.at(0).at(0).value<IpcChannel::Failure>(), IpcChannel::ServiceUnavailable);
    missing.close();
    QTest::qWait(100);
    QCOMPARE(m_server->peerCount(), qsizetype(0));
#endif
}

void TstIpcClient::tokenReaderRules()
{
    const IpcServerPolicy same = IpcServerPolicy::sameUser();
    QVERIFY(writeToken("tok-A\n"));
    QCOMPARE(ipcReadToken(m_tokenPath, same).value_or(QByteArray()), QByteArray("tok-A"));
    QVERIFY(writeToken("tok-A\r\n"));
    QCOMPARE(ipcReadToken(m_tokenPath, same).value_or(QByteArray()), QByteArray("tok-A"));
    QVERIFY(writeToken("tok A"));
    QVERIFY(!ipcReadToken(m_tokenPath, same).has_value());
    QVERIFY(writeToken("tok-A\n\n"));
    QVERIFY(!ipcReadToken(m_tokenPath, same).has_value());
    QVERIFY(writeToken(""));
    QVERIFY(!ipcReadToken(m_tokenPath, same).has_value());
    QVERIFY(writeToken(QByteArray(513, 'a')));
    QVERIFY(!ipcReadToken(m_tokenPath, same).has_value());
    QVERIFY(writeToken(QByteArray(512, 'a')));
    QVERIFY(ipcReadToken(m_tokenPath, same).has_value());
    QVERIFY(!ipcReadToken(m_tokenDir->filePath("absent"), same).has_value());
#ifndef Q_OS_WIN
    // A file owned by this (non-root) user is not a privileged host's token.
    if (::geteuid() != 0) {
        QVERIFY(writeToken("tok-A"));
        QVERIFY(!ipcReadToken(m_tokenPath, IpcServerPolicy::privileged()).has_value());
    }
#endif
}

void TstIpcClient::windowsConnectorSourceRules()
{
    QFile f(QStringLiteral(CYSEC_GUI_UI_SOURCE_DIR "/ipcconnect_win.cpp"));
    QVERIFY(f.open(QIODevice::ReadOnly | QIODevice::Text));
    const QByteArray src = f.readAll();
    QVERIFY(src.contains("SECURITY_SQOS_PRESENT"));
    QVERIFY(src.contains("SECURITY_IDENTIFICATION"));
    QVERIFY(src.contains("GetNamedPipeServerProcessId"));
    QVERIFY(src.contains("setSocketDescriptor"));
    for (const QByteArray &line : src.split('\n')) {
        if (line.trimmed().startsWith("//"))
            continue;
        QVERIFY2(!line.contains("connectToServer"), line.constData());
    }

    for (const char *name : {"ipcconnect_unix.cpp", "ipcconnect_win.cpp", "ipcchannel.cpp"}) {
        QFile other(QStringLiteral(CYSEC_GUI_UI_SOURCE_DIR "/") + QLatin1StringView(name));
        QVERIFY(other.open(QIODevice::ReadOnly));
        QVERIFY2(!other.readAll().contains("AbstractNamespace"), name);
    }
}

// QTEST_MAIN (QGuiApplication) because ctest passes -platform offscreen.
QTEST_MAIN(TstIpcClient)
#include "tst_ipcclient.moc"
