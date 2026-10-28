// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hostmodel.h"
#include "logmodel.h"
#include "scanbackend.h"

#include <QObject>
#include <QString>
#include <QStringList>
#include <QtQml/qqmlregistration.h>

// ScanSession is the single object QML drives a scan through. It owns the
// host and log models, folds backend events into stage progress, and keeps
// the result state (completed, partial, failed) plus whether the results
// have been exported yet.
//
// It holds a ScanBackend pointer only, never a concrete transport, so the
// process transport can be swapped for local IPC without touching QML.
//
// Contract fixed by plan 13-07; implemented in plan 13-15.
class ScanSession : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    Q_PROPERTY(ScanBackend *backend READ backend WRITE setBackend NOTIFY backendChanged FINAL)
    Q_PROPERTY(HostModel *hosts READ hosts CONSTANT FINAL)
    Q_PROPERTY(LogModel *log READ log CONSTANT FINAL)
    Q_PROPERTY(State state READ state NOTIFY stateChanged FINAL)

    Q_PROPERTY(int currentStageIndex READ currentStageIndex NOTIFY progressChanged FINAL)
    Q_PROPERTY(QString currentStage READ currentStage NOTIFY progressChanged FINAL)
    Q_PROPERTY(int stageDone READ stageDone NOTIFY progressChanged FINAL)
    Q_PROPERTY(int stageTotal READ stageTotal NOTIFY progressChanged FINAL)
    Q_PROPERTY(int elapsedSeconds READ elapsedSeconds NOTIFY elapsedSecondsChanged FINAL)
    Q_PROPERTY(int hostsFound READ hostsFound NOTIFY hostsFoundChanged FINAL)

    Q_PROPERTY(bool capabilitiesKnown READ capabilitiesKnown NOTIFY capabilitiesChanged FINAL)
    Q_PROPERTY(bool unprivilegedIcmp READ unprivilegedIcmp NOTIFY capabilitiesChanged FINAL)

    Q_PROPERTY(bool hasPayload READ hasPayload NOTIFY payloadChanged FINAL)
    Q_PROPERTY(QString payloadPath READ payloadPath NOTIFY payloadChanged FINAL)
    Q_PROPERTY(bool partial READ partial NOTIFY stateChanged FINAL)

    Q_PROPERTY(Failure failure READ failure NOTIFY failureChanged FINAL)
    Q_PROPERTY(int exitCode READ exitCode NOTIFY failureChanged FINAL)
    Q_PROPERTY(QString failureDetail READ failureDetail NOTIFY failureChanged FINAL)

    Q_PROPERTY(bool resultsExported READ resultsExported NOTIFY exportStateChanged FINAL)
    Q_PROPERTY(bool hasUnexportedResults READ hasUnexportedResults NOTIFY exportStateChanged FINAL)
    Q_PROPERTY(QStringList scope READ scope NOTIFY scopeChanged FINAL)

public:
    enum State { Idle, Running, Stopping, Completed, Partial, Failed };
    Q_ENUM(State)

    enum Failure {
        NoFailure,
        EngineNotFound,
        EngineFailedToStart,
        EngineExitedNonZero,
        EngineRejectedInput,
    };
    Q_ENUM(Failure)

    explicit ScanSession(QObject *parent = nullptr);
    ~ScanSession() override;

    ScanBackend *backend() const;
    void setBackend(ScanBackend *backend);

    HostModel *hosts() const;
    LogModel *log() const;
    State state() const;

    int currentStageIndex() const;
    QString currentStage() const;
    int stageDone() const;
    int stageTotal() const;
    int elapsedSeconds() const;
    int hostsFound() const;

    bool capabilitiesKnown() const;
    bool unprivilegedIcmp() const;

    bool hasPayload() const;
    QString payloadPath() const;
    bool partial() const;

    Failure failure() const;
    int exitCode() const;
    QString failureDetail() const;

    bool resultsExported() const;
    bool hasUnexportedResults() const;
    QStringList scope() const;

    Q_INVOKABLE void start(const QStringList &cidrs, const QString &portSpec, bool probeFragile);
    Q_INVOKABLE void stop();
    Q_INVOKABLE void markExported();
    Q_INVOKABLE void discardResults();

signals:
    void backendChanged();
    void stateChanged();
    void progressChanged();
    void elapsedSecondsChanged();
    void hostsFoundChanged();
    void capabilitiesChanged();
    void payloadChanged();
    void failureChanged();
    void exportStateChanged();
    void scopeChanged();
    // Emitted after the final payload was folded into the host model.
    void reconciled(bool changed);

private:
    ScanBackend *m_backend = nullptr;
    HostModel *m_hosts = nullptr;
    LogModel *m_log = nullptr;
    State m_state = Idle;

    int m_currentStageIndex = -1;
    QString m_currentStage;
    int m_stageDone = 0;
    int m_stageTotal = 0;
    int m_elapsedSeconds = 0;
    int m_hostsFound = 0;

    bool m_capabilitiesKnown = false;
    bool m_unprivilegedIcmp = false;

    QString m_payloadPath;

    Failure m_failure = NoFailure;
    int m_exitCode = 0;
    QString m_failureDetail;

    bool m_resultsExported = false;
    QStringList m_scope;
};
