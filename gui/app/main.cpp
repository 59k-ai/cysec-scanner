// Copyright 2026 59k GmbH
// SPDX-License-Identifier: Apache-2.0

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QtQml/qqmlextensionplugin.h>

Q_IMPORT_QML_PLUGIN(Cysec_Scanner_UiPlugin)

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QGuiApplication::setOrganizationName(QStringLiteral("59k"));
    QGuiApplication::setApplicationName(QStringLiteral("cysec-scanner-gui"));
    QGuiApplication::setApplicationVersion(QStringLiteral(CYSEC_SCANNER_GUI_VERSION));

    // Basic is identical on every desktop platform and fully restylable;
    // native styles ignore the theme. Must be set before the engine loads.
    QQuickStyle::setStyle(QStringLiteral("Basic"));

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed, &app,
        [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine.loadFromModule("Cysec.Scanner.App", "Main");

    return app.exec();
}
