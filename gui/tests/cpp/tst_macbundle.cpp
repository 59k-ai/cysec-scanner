// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

// macOS only: the built app bundle must be something Local Network privacy
// can track.
//
// macOS decides per app whether a process may reach other hosts on the LAN,
// and it attributes the engine child to the app that launched it. The user's
// Allow/Deny decision is stored against the app's code signing identifier.
// The linker's ad-hoc signature names the bare executable
// ("cysec-scanner-gui"), not the bundle identifier, and leaves Info.plist
// unbound, so the stored decision never matches and every peer except the
// gateway and the Mac itself answers "no route to host". A scan of a busy
// LAN then shows two hosts and no names (UAT 13 step 3).
//
// So the bundle must be signed as a bundle: identifier == CFBundleIdentifier,
// Info.plist bound, nested engine signed, and it must explain the access in
// NSLocalNetworkUsageDescription so a fresh machine gets a meaningful prompt.

#include <QFileInfo>
#include <QProcess>
#include <QString>
#include <QtTest>

#ifndef CYSEC_GUI_BUNDLE_DIR
#error "tst_macbundle needs CYSEC_GUI_BUNDLE_DIR"
#endif
#ifndef CYSEC_GUI_BUNDLE_ID
#error "tst_macbundle needs CYSEC_GUI_BUNDLE_ID"
#endif

class TstMacBundle : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void infoPlistExplainsLocalNetworkAccess();
    void signatureIdentifierIsBundleId();
    void signatureBindsInfoPlist();
    void signatureVerifies();
    void nestedEngineSigned();

private:
    struct Run
    {
        int exitCode = -1;
        QString out;
        QString err;
    };
    static Run run(const QString &program, const QStringList &args);
    static QString bundle() { return QStringLiteral(CYSEC_GUI_BUNDLE_DIR); }
};

TstMacBundle::Run TstMacBundle::run(const QString &program, const QStringList &args)
{
    QProcess p;
    p.start(program, args);
    Run r;
    if (!p.waitForFinished(30000))
        return r;
    r.exitCode = p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1;
    r.out = QString::fromUtf8(p.readAllStandardOutput());
    r.err = QString::fromUtf8(p.readAllStandardError());
    return r;
}

void TstMacBundle::initTestCase()
{
    QVERIFY2(QFileInfo(bundle()).isDir(), qPrintable(bundle()));
}

void TstMacBundle::infoPlistExplainsLocalNetworkAccess()
{
    const Run r = run(QStringLiteral("/usr/bin/plutil"),
                      {QStringLiteral("-extract"), QStringLiteral("NSLocalNetworkUsageDescription"),
                       QStringLiteral("raw"), bundle() + QStringLiteral("/Contents/Info.plist")});
    QVERIFY2(r.exitCode == 0, qPrintable(r.err + r.out));
    QVERIFY(!r.out.trimmed().isEmpty());
}

void TstMacBundle::signatureIdentifierIsBundleId()
{
    const Run r = run(QStringLiteral("/usr/bin/codesign"),
                      {QStringLiteral("-dv"), QStringLiteral("--verbose=2"), bundle()});
    QVERIFY2(r.exitCode == 0, qPrintable(r.err));
    // codesign -d reports on stderr.
    QVERIFY2(r.err.contains(QStringLiteral("\nIdentifier=") + QStringLiteral(CYSEC_GUI_BUNDLE_ID)
                            + QLatin1Char('\n')),
             qPrintable(r.err));
    QVERIFY2(!r.err.contains(QStringLiteral("linker-signed")), qPrintable(r.err));
}

void TstMacBundle::signatureBindsInfoPlist()
{
    const Run r = run(QStringLiteral("/usr/bin/codesign"),
                      {QStringLiteral("-dv"), QStringLiteral("--verbose=2"), bundle()});
    QVERIFY2(r.exitCode == 0, qPrintable(r.err));
    QVERIFY2(!r.err.contains(QStringLiteral("Info.plist=not bound")), qPrintable(r.err));
}

void TstMacBundle::signatureVerifies()
{
    const Run r = run(QStringLiteral("/usr/bin/codesign"),
                      {QStringLiteral("--verify"), QStringLiteral("--strict"), bundle()});
    QVERIFY2(r.exitCode == 0, qPrintable(r.err));
}

void TstMacBundle::nestedEngineSigned()
{
    const QString engine = bundle() + QStringLiteral("/Contents/MacOS/cysec-scanner");
    if (!QFileInfo(engine).isFile())
        QSKIP("no engine bundled (configure with CYSEC_GUI_BUNDLE_ENGINE to ship one)");
    const Run r = run(QStringLiteral("/usr/bin/codesign"),
                      {QStringLiteral("--verify"), QStringLiteral("--strict"), engine});
    QVERIFY2(r.exitCode == 0, qPrintable(r.err));
}

QTEST_MAIN(TstMacBundle)
#include "tst_macbundle.moc"
