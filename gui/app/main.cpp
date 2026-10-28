// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include "engineinfo.h"
#include "languagecontroller.h"
#include "processscanbackend.h"
#include "scansession.h"

#include <QFile>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QString>
#include <QVariant>
#include <QtQml/qqmlextensionplugin.h>

Q_IMPORT_QML_PLUGIN(Cysec_Scanner_UiPlugin)

namespace {

// The About dialog's third-party notices, read here so QML needs no file
// access (QML_XHR_ALLOW_FILE_READ stays unset in the app).
QString readNotices()
{
    QFile file(QStringLiteral(":/qt/qml/Cysec/Scanner/Ui/THIRD_PARTY_NOTICES.md"));
    if (!file.open(QIODevice::ReadOnly))
        return QString();
    return QString::fromUtf8(file.readAll());
}

} // namespace

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QGuiApplication::setOrganizationName(QStringLiteral("59k"));
    QGuiApplication::setApplicationName(QStringLiteral("cysec-scanner-gui"));
    QGuiApplication::setApplicationVersion(QStringLiteral(CYSEC_SCANNER_GUI_VERSION));

    // Basic is identical on every desktop platform and fully restylable;
    // native styles ignore the theme. Must be set before the engine loads.
    QQuickStyle::setStyle(QStringLiteral("Basic"));

    // The transport is built here and handed to the session through the
    // abstract seam; QML only ever sees the session (D-18). Parented to the
    // app so they outlive the QML engine declared below.
    auto *backend = new ProcessScanBackend(&app);
    auto *session = new ScanSession(&app);
    session->setBackend(backend);
    auto *engineInfo = new EngineInfo(&app);
    engineInfo->refresh();

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed, &app,
        [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);

    // Create the language singleton now so the persisted language is
    // installed before the first frame is built.
    engine.singletonInstance<LanguageController *>("Cysec.Scanner.Ui", "LanguageController");

    engine.setInitialProperties({
        {QStringLiteral("session"), QVariant::fromValue(session)},
        {QStringLiteral("engineInfo"), QVariant::fromValue(engineInfo)},
        {QStringLiteral("noticesText"), readNotices()},
    });
    engine.loadFromModule("Cysec.Scanner.App", "Main");

    return app.exec();
}
