// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <QList>
#include <QMetaType>
#include <QString>
#include <QStringList>

// Plain C++ value types for one decoded line of the engine's detailed NDJSON
// progress stream. The wire kinds are phase_start, phase_done, agent_start,
// agent_done, scan_start, stage_progress, host, log and scan_end; anything
// else decodes to Unknown so a newer engine never breaks an older GUI.
// Stages announced by scan_start are discovery, port and fingerprint.
//
// Contract fixed by plan 13-07; decoding is implemented in plan 13-09.

enum class ScanEventKind {
    PhaseStart,
    PhaseDone,
    AgentStart,
    AgentDone,
    ScanStart,
    StageProgress,
    Host,
    Log,
    ScanEnd,
    Unknown,
};

struct ServiceFact
{
    int port = 0;
    QString protocol;
    QString serviceName;
    QString product;
    QString version;
};

struct HostFact
{
    QString ip;
    QString externalId;
    QString hostname;
    QString mac;
    QString macVendor;
    QString osGuess;
    double osGuessConfidence = -1.0; // negative when the engine sent none
    QList<ServiceFact> services;
    bool servicesKnown = false; // false until a stage has reported services
};

struct ScanEvent
{
    ScanEventKind kind = ScanEventKind::Unknown;
    int seq = -1;
    double ts = 0;
    QString agent;

    // stage_progress counters (agent carries the stage name).
    int done = 0;
    int total = 0;

    // host
    HostFact host;

    // log
    QString logLevel;
    QString logMessage;

    // scan_end
    QString endStatus;
    QString endError;
    int endAssets = 0;

    // scan_start
    QStringList scope;
    QStringList stages;
    bool hasCapabilities = false;
    bool capUnprivilegedIcmp = false;
    bool capSystemPing = false;
    bool capArpCache = false;
};

Q_DECLARE_METATYPE(ScanEvent)
