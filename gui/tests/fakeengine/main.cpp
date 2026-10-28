// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// cysec-fake-engine: a stand-in for the scanner CLI, used only by the GUI
// transport tests. Behaviour comes from environment variables, which the
// child inherits from the test process:
//
//   FAKE_ENGINE_FIXTURE        NDJSON file replayed to stdout, flushed per line
//   FAKE_ENGINE_PAYLOAD        JSON copied to --payload-out on normal completion
//   FAKE_ENGINE_CANCEL_PAYLOAD JSON copied to --payload-out on cancel (exit 130)
//   FAKE_ENGINE_DELAY_MS       pause between replayed lines
//   FAKE_ENGINE_HOLD_MS        pause after the replay before exiting (cancellable)
//   FAKE_ENGINE_EXIT_CODE      exit code on normal completion (default 0)
//   FAKE_ENGINE_IGNORE_STDIN   "1": never watch stdin; on POSIX also ignore SIGTERM
//   FAKE_ENGINE_STDERR_BYTES   bytes of diagnostic lines written to stderr first
//   FAKE_ENGINE_ARGV_OUT       file that receives argv (one argument per line)
//   FAKE_ENGINE_PID_OUT        file that receives the process id
//   FAKE_ENGINE_DESCRIBE       printed for --describe (a file path or literal JSON)
//
// Cooperative cancel mirrors --cancel-on-stdin-eof: stdin EOF (or SIGTERM on
// POSIX) stops the replay, writes the cancel payload and exits 130.

#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QString>
#include <QStringList>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <thread>

namespace {

std::atomic<bool> g_cancel{false};

extern "C" void onTerm(int)
{
    g_cancel.store(true);
}

int envInt(const char *name, int fallback)
{
    bool ok = false;
    const int v = qEnvironmentVariableIntValue(name, &ok);
    return ok ? v : fallback;
}

QString envStr(const char *name)
{
    return qEnvironmentVariable(name);
}

void writeFile(const QString &path, const QByteArray &data)
{
    if (path.isEmpty())
        return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(data);
}

void copyPayload(const QString &from, const QString &to)
{
    if (from.isEmpty() || to.isEmpty())
        return;
    QFile src(from);
    if (src.open(QIODevice::ReadOnly))
        writeFile(to, src.readAll());
}

// Sleeps up to ms, waking early when a cancel arrives. Returns true if
// cancelled.
bool waitCancellable(int ms)
{
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < until) {
        if (g_cancel.load())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return g_cancel.load();
}

[[noreturn]] void finish(int code)
{
    std::fflush(stdout);
    std::fflush(stderr);
    std::_Exit(code);
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments().mid(1);

    if (args.contains(QStringLiteral("--describe"))) {
        const QString describe = envStr("FAKE_ENGINE_DESCRIBE");
        QByteArray out = describe.toUtf8();
        QFile f(describe);
        if (!describe.isEmpty() && f.exists() && f.open(QIODevice::ReadOnly))
            out = f.readAll();
        std::fwrite(out.constData(), 1, size_t(out.size()), stdout);
        std::fputc('\n', stdout);
        finish(0);
    }

    QString payloadOut;
    const qsizetype idx = args.indexOf(QStringLiteral("--payload-out"));
    if (idx >= 0 && idx + 1 < args.size())
        payloadOut = args.at(idx + 1);

    writeFile(envStr("FAKE_ENGINE_ARGV_OUT"), args.join(QLatin1Char('\n')).toUtf8() + '\n');
    writeFile(envStr("FAKE_ENGINE_PID_OUT"), QByteArray::number(app.applicationPid()));

    const bool ignoreStdin = envStr("FAKE_ENGINE_IGNORE_STDIN") == QLatin1String("1");
    if (ignoreStdin) {
#ifndef Q_OS_WIN
        std::signal(SIGTERM, SIG_IGN);
#endif
    } else {
#ifndef Q_OS_WIN
        std::signal(SIGTERM, onTerm);
#endif
        std::thread([] {
            char buf[256];
            while (std::fread(buf, 1, sizeof buf, stdin) > 0) {
            }
            g_cancel.store(true); // stdin EOF is the portable cancel channel
        }).detach();
    }

    const int stderrBytes = envInt("FAKE_ENGINE_STDERR_BYTES", 0);
    for (int written = 0, n = 0; written < stderrBytes; ++n) {
        // Control characters are deliberate: the GUI must strip them.
        const QByteArray line =
            "diag\x1b[31m line " + QByteArray::number(n) + "\x07 with\ttab padding padding\n";
        std::fwrite(line.constData(), 1, size_t(line.size()), stderr);
        written += int(line.size());
    }
    std::fflush(stderr);

    const QString cancelPayload = envStr("FAKE_ENGINE_CANCEL_PAYLOAD");
    const auto cancelNow = [&] {
        copyPayload(cancelPayload, payloadOut);
        finish(130);
    };

    const int delayMs = envInt("FAKE_ENGINE_DELAY_MS", 0);
    const QString fixture = envStr("FAKE_ENGINE_FIXTURE");
    if (!fixture.isEmpty()) {
        QFile f(fixture);
        if (f.open(QIODevice::ReadOnly)) {
            while (!f.atEnd()) {
                if (g_cancel.load())
                    cancelNow();
                const QByteArray line = f.readLine();
                if (line.trimmed().isEmpty())
                    continue;
                std::fwrite(line.constData(), 1, size_t(line.size()), stdout);
                if (!line.endsWith('\n'))
                    std::fputc('\n', stdout);
                std::fflush(stdout);
                if (delayMs > 0 && waitCancellable(delayMs))
                    cancelNow();
            }
        }
    }

    if (waitCancellable(envInt("FAKE_ENGINE_HOLD_MS", 0)))
        cancelNow();

    const int exitCode = envInt("FAKE_ENGINE_EXIT_CODE", 0);
    if (exitCode == 0)
        copyPayload(envStr("FAKE_ENGINE_PAYLOAD"), payloadOut);
    finish(exitCode);
}
