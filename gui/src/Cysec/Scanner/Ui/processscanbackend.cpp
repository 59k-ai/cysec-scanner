// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "processscanbackend.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>

// v0 transport behind the D-18 seam: the engine CLI as a child process.
//
// Trust model. The engine binary is resolved only from CYSEC_SCANNER_BIN or
// the directory of the running GUI, never from PATH or the working directory
// (D-16, binary planting). It is spawned with a QStringList argv, so no shell
// ever parses user input. Its stdout and stderr are untrusted bytes: stdout
// goes through the bounded NdjsonLineBuffer, stderr is drained continuously
// into a capped, control-character-free ring so a chatty child can neither
// deadlock on a full pipe nor grow GUI memory.
//
// Cancel (D-27). stdin stays open for the whole scan and is the portable
// cancel channel: the engine runs with --cancel-on-stdin-eof, so closing it
// asks for a cooperative stop on every OS. POSIX additionally gets SIGTERM.
// Windows does not, because QProcess::terminate() only posts WM_CLOSE, which
// a console child never sees. Whatever the child does, kill() follows after
// the grace period, and the destructor kills too, so no scan outlives the GUI.

namespace {

// Cap on the stderr ring and on one diagnostic line.
constexpr qsizetype kDiagnosticsMaxBytes = 64 * 1024;
constexpr qsizetype kDiagnosticLineMaxChars = 512;
constexpr int kDiagnosticsTailLines = 20;
constexpr int kExitCancelled = 130;

QString sanitiseDiagnostic(const QByteArray &raw)
{
    const QString text = QString::fromUtf8(raw);
    QString out;
    out.reserve(qMin(text.size(), kDiagnosticLineMaxChars));
    for (const QChar c : text) {
        if (out.size() >= kDiagnosticLineMaxChars)
            break;
        if (c == QLatin1Char('\t')) {
            out.append(QLatin1Char(' '));
            continue;
        }
        const QChar::Category cat = c.category();
        if (cat == QChar::Other_Control || cat == QChar::Other_Format
            || cat == QChar::Separator_Line || cat == QChar::Separator_Paragraph)
            continue;
        out.append(c);
    }
    return out.trimmed();
}

} // namespace

ProcessScanBackend::ProcessScanBackend(QObject *parent)
    : ScanBackend(parent)
    , m_process(new QProcess(this))
    , m_killTimer(new QTimer(this))
{
    // Belt and braces next to the static registration in scanbackend.cpp.
    qRegisterMetaType<ScanEvent>("ScanEvent");

    m_process->setProcessChannelMode(QProcess::SeparateChannels);
    m_killTimer->setSingleShot(true);

    connect(m_process, &QProcess::readyReadStandardOutput, this, &ProcessScanBackend::onStdout);
    connect(m_process, &QProcess::readyReadStandardError, this, &ProcessScanBackend::onStderr);
    connect(m_process, &QProcess::finished, this, &ProcessScanBackend::onFinished);
    connect(m_process, &QProcess::errorOccurred, this, &ProcessScanBackend::onErrorOccurred);
    connect(m_killTimer, &QTimer::timeout, this, [this] {
        if (m_process->state() != QProcess::NotRunning)
            m_process->kill();
    });
}

ProcessScanBackend::~ProcessScanBackend()
{
    // No signals from a half-destroyed object; just make sure the child dies
    // and is reaped before the temporary directory goes away.
    m_killTimer->stop();
    m_process->disconnect(this);
    if (m_process->state() != QProcess::NotRunning) {
        m_process->kill();
        m_process->waitForFinished(1000);
    }
}

QString ProcessScanBackend::resolveEnginePath()
{
    const QString env = qEnvironmentVariable("CYSEC_SCANNER_BIN");
    if (!env.isEmpty()) {
        // An explicit override never falls back to anything else.
        const QFileInfo fi(env);
        return (fi.isFile() && fi.isExecutable()) ? fi.absoluteFilePath() : QString();
    }
    // Next to the GUI executable only (Contents/MacOS inside a macOS bundle).
    // findExecutable adds the platform suffix (.exe) and searches exactly the
    // one directory given here.
    return QStandardPaths::findExecutable(QStringLiteral("cysec-scanner"),
                                          {QCoreApplication::applicationDirPath()});
}

void ProcessScanBackend::setEnginePath(const QString &path)
{
    m_enginePath = path;
}

void ProcessScanBackend::setStopGraceMs(int ms)
{
    m_stopGraceMs = qMax(0, ms);
}

QStringList ProcessScanBackend::buildArguments(const ScanRequest &r, const QString &payloadPath)
{
    // One argv element per value; no shell, no quoting. No timing flag is
    // ever passed: the engine's defaults are the only profile (D-12).
    QStringList args{
        QStringLiteral("--payload-out"),
        payloadPath,
        QStringLiteral("--events=detailed"),
        QStringLiteral("--cancel-on-stdin-eof"),
    };
    for (const QString &cidr : r.cidrs) {
        args << QStringLiteral("--cidr") << cidr;
    }
    if (!r.portSpec.isEmpty())
        args << QStringLiteral("--ports") << r.portSpec;
    if (r.probeFragile)
        args << QStringLiteral("--probe-fragile");
    return args;
}

void ProcessScanBackend::start(const ScanRequest &request)
{
    if (isRunning())
        return;

    m_killTimer->stop();
    m_stopRequested = false;
    m_overflowReported = false;
    m_stdoutBuffer.reset();
    m_stderrPending.clear();
    m_diagnostics.clear();
    m_diagnosticsBytes = 0;

    QString engine;
    if (!m_enginePath.isEmpty()) {
        const QFileInfo fi(m_enginePath);
        if (fi.isFile() && fi.isExecutable())
            engine = fi.absoluteFilePath();
    } else {
        engine = resolveEnginePath();
    }
    if (engine.isEmpty()) {
        emit failedToStart(EngineNotFound);
        return;
    }

    // One private directory per scan; the previous scan's payload stays
    // readable until the next start.
    m_tempDir = std::make_unique<QTemporaryDir>();
    if (!m_tempDir->isValid()) {
        appendDiagnostic(QByteArrayLiteral("could not create a temporary directory for the payload"));
        emit failedToStart(EngineFailedToStart);
        return;
    }
    m_payloadPath = m_tempDir->filePath(QStringLiteral("payload.json"));

    m_process->setProgram(engine);
    m_process->setArguments(buildArguments(request, m_payloadPath));
    // ReadWrite keeps stdin open: closing it later is the cancel request.
    m_process->start(QIODevice::ReadWrite);
}

void ProcessScanBackend::requestStop()
{
    if (!isRunning() || m_stopRequested)
        return;
    m_stopRequested = true;
    m_process->closeWriteChannel(); // stdin EOF -> cooperative cancel (all OSes)
#ifndef Q_OS_WIN
    m_process->terminate(); // SIGTERM as a second cooperative signal on POSIX
#endif
    m_killTimer->start(m_stopGraceMs);
}

bool ProcessScanBackend::isRunning() const
{
    return m_process->state() != QProcess::NotRunning;
}

QStringList ProcessScanBackend::diagnosticsTail() const
{
    return m_diagnostics.mid(qMax(0, m_diagnostics.size() - kDiagnosticsTailLines));
}

void ProcessScanBackend::onStdout()
{
    processLines(m_stdoutBuffer.append(m_process->readAllStandardOutput()));
}

void ProcessScanBackend::processLines(const QList<QByteArray> &lines)
{
    if (m_stdoutBuffer.overflowed() && !m_overflowReported) {
        m_overflowReported = true;
        appendDiagnostic(QByteArrayLiteral("dropped an oversized progress line from the engine"));
    }
    for (const QByteArray &line : lines) {
        const std::optional<ScanEvent> ev = NdjsonParser::parseLine(line);
        // Malformed lines and kinds from a newer engine are skipped, not fatal.
        if (!ev || ev->kind == ScanEventKind::Unknown)
            continue;
        emit eventReceived(*ev);
    }
}

void ProcessScanBackend::onStderr()
{
    m_stderrPending += m_process->readAllStandardError();
    qsizetype nl;
    while ((nl = m_stderrPending.indexOf('\n')) >= 0) {
        appendDiagnostic(m_stderrPending.left(nl));
        m_stderrPending.remove(0, nl + 1);
    }
    // A child that never writes a newline still cannot grow this buffer.
    if (m_stderrPending.size() > kDiagnosticLineMaxChars * 4)
        flushStderrPending();
}

void ProcessScanBackend::flushStderrPending()
{
    if (!m_stderrPending.isEmpty())
        appendDiagnostic(m_stderrPending);
    m_stderrPending.clear();
}

void ProcessScanBackend::appendDiagnostic(const QByteArray &raw)
{
    const QString line = sanitiseDiagnostic(raw);
    if (line.isEmpty())
        return;
    m_diagnostics.append(line);
    m_diagnosticsBytes += line.size() * qsizetype(sizeof(QChar));
    while (m_diagnosticsBytes > kDiagnosticsMaxBytes && m_diagnostics.size() > 1) {
        m_diagnosticsBytes -= m_diagnostics.first().size() * qsizetype(sizeof(QChar));
        m_diagnostics.removeFirst();
    }
}

void ProcessScanBackend::onErrorOccurred(QProcess::ProcessError error)
{
    // Only a failed start is reported here; crashes and kills arrive through
    // finished(). QProcess emits no finished() after FailedToStart.
    if (error == QProcess::FailedToStart) {
        m_killTimer->stop();
        emit failedToStart(EngineFailedToStart);
    }
}

void ProcessScanBackend::onFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    m_killTimer->stop();

    // Drain what is left; a final line without a newline still counts.
    QByteArray rest = m_process->readAllStandardOutput();
    rest.append('\n');
    processLines(m_stdoutBuffer.append(rest));
    m_stderrPending += m_process->readAllStandardError();
    onStderr();
    flushStderrPending();

    const bool normal = exitStatus == QProcess::NormalExit;
    if (!normal && exitCode == 0)
        exitCode = -1; // a crash or kill never reads as success

    EndStatus status = Failed;
    if (normal && exitCode == 0)
        status = Completed;
    else if (exitCode == kExitCancelled || m_stopRequested)
        status = Cancelled;

    QString payload;
    const QFileInfo fi(m_payloadPath);
    if (!m_payloadPath.isEmpty() && fi.isFile() && fi.size() > 0)
        payload = m_payloadPath;

    emit finished(status, exitCode, payload);
}
