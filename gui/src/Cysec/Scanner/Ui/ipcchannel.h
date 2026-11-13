// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcendpoint.h"
#include "ndjsonparser.h"

#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QString>
#include <QTimer>

class QLocalSocket;

// IpcChannel: one client session with a local IPC host speaking the
// newline-delimited JSON-RPC 2.0 wire contract, protocol 1.
//
// open() reads the token file, connects through ipcConnect (which verifies
// the server before anything is written), sends session.hello and becomes
// Ready when the host accepts protocol 1. Afterwards call() sends requests
// whose answers arrive as replied() or callFailed() with the same id, and
// server notifications arrive as notification().
//
// Every server line is untrusted: a line that is not a JSON-RPC 2.0 object
// of the expected shape, or a line above NdjsonLineBuffer::kMaxLineBytes,
// ends the session with ProtocolError. The class renders nothing; all text
// it hands out is data.
//
// After a failure or a session.closing notice the channel reconnects with
// exponential backoff (re-reading the token each time) until close(). Two
// outcomes stop retrying: an invalid address and a protocol mismatch.

class IpcChannel : public QObject
{
    Q_OBJECT

public:
    enum State { Disconnected, Connecting, Authenticating, Ready, Backoff };
    Q_ENUM(State)

    enum Failure {
        NoFailure,
        ServiceUnavailable,
        NotAuthorized,
        ProtocolMismatch,
        ServerNotTrusted,
        ProtocolError,
    };
    Q_ENUM(Failure)

    explicit IpcChannel(IpcEndpoint endpoint, QObject *parent = nullptr);
    ~IpcChannel() override;

    void open();
    void close();

    State state() const;
    Failure lastFailure() const;

    // Why the last call() returned -1. A caller tells "will never fit" from
    // "the session is gone" by this, never by state(): while a teardown fails
    // the pending calls the state still reads Ready but there is no socket.
    enum class CallError { None, NotReady, TooLarge, WriteFailed };
    Q_ENUM(CallError)

    // Sends one request. Returns its id, or -1 (and sends nothing) when the
    // channel is not Ready, the write fails, or the serialized request is
    // over the host's 64 KiB request line limit; lastCallError() says which.
    qint64 call(const QString &method, const QJsonObject &params);
    CallError lastCallError() const;

    QJsonObject helloResult() const;

    void setBackoff(int initialMs, int maxMs);

signals:
    void stateChanged(IpcChannel::State state);
    void ready();
    void failure(IpcChannel::Failure failure);
    void replied(qint64 id, const QJsonObject &result);
    void callFailed(qint64 id, int code, const QString &message, const QJsonObject &data);
    void notification(const QString &method, const QJsonObject &params);
    void closing(int code, const QString &reason);

private:
    enum class Retry { Yes, No };

    void attempt();
    void onReadyRead();
    void onDisconnected();
    void onHelloTimeout();
    // Returns false when the line ended the session.
    bool handleLine(const QByteArray &line);
    void handleHelloAnswer(const QJsonObject &message);
    bool writeMessage(const QJsonObject &message);
    void teardown();
    void fail(Failure f, Retry retry);
    void scheduleReconnect();
    void setState(State s);

    IpcEndpoint m_endpoint;
    QPointer<QLocalSocket> m_socket;
    NdjsonLineBuffer m_lines;
    QTimer m_reconnectTimer;
    QTimer m_helloTimer;
    State m_state = Disconnected;
    Failure m_lastFailure = NoFailure;
    QJsonObject m_helloResult;
    QSet<qint64> m_pending;
    CallError m_lastCallError = CallError::None;
    qint64 m_nextId = 1;
    qint64 m_helloId = -1;
    quint64 m_generation = 0;
    int m_backoffInitialMs = 500;
    int m_backoffMaxMs = 10000;
    int m_backoffMs = 500;
    bool m_wantOpen = false;
};
