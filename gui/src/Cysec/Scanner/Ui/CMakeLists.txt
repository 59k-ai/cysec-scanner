# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Cysec.Scanner.Ui: the reusable STATIC QML module. STATIC means qmlcachegen
# compiles everything in and consumers deploy no separate plugin; they link
# cysec_scanner_uiplugin and Q_IMPORT_QML_PLUGIN(Cysec_Scanner_UiPlugin).

set_source_files_properties(Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

# The About dialog shows the repository's third-party notices. The file lives
# at the repo root; the alias makes it reachable as
# qrc:/qt/qml/Cysec/Scanner/Ui/THIRD_PARTY_NOTICES.md.
set(CYSEC_NOTICES_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../THIRD_PARTY_NOTICES.md")
set_source_files_properties("${CYSEC_NOTICES_FILE}" PROPERTIES
    QT_RESOURCE_ALIAS "THIRD_PARTY_NOTICES.md")

qt_add_qml_module(cysec_scanner_ui
    URI Cysec.Scanner.Ui
    VERSION 1.0
    STATIC
    QML_FILES
        Theme.qml
        PlainLabel.qml
        PrimaryButton.qml
        SecondaryButton.qml
        DestructiveButton.qml
        StatusBadge.qml
        LabeledField.qml
        CapabilityBanner.qml
        ProgressPanel.qml
        ResultsTable.qml
        DetailPanel.qml
        LogPanel.qml
        ConfirmDialog.qml
        AboutDialog.qml
        SettingsMenu.qml
        ExportSheet.qml
        SetupBar.qml
        ScannerView.qml
    SOURCES
        appearance.h
        appearance.cpp
        scanevent.h
        ndjsonparser.h
        ndjsonparser.cpp
        scanbackend.h
        scanbackend.cpp
        processscanbackend.h
        processscanbackend.cpp
        hostmodel.h
        hostmodel.cpp
        logmodel.h
        logmodel.cpp
        scansession.h
        scansession.cpp
        hostfilterproxy.h
        hostfilterproxy.cpp
        hosttableadapter.h
        hosttableadapter.cpp
        engineinfo.h
        engineinfo.cpp
        validators.h
        validators.cpp
        exporter.h
        exporter.cpp
        languagecontroller.h
        languagecontroller.cpp
        formatter.h
        formatter.cpp
    RESOURCES
        fonts/IBMPlexSans-Regular.ttf
        fonts/IBMPlexSans-SemiBold.ttf
        fonts/IBMPlexMono-Regular.ttf
        fonts/IBMPlexMono-SemiBold.ttf
        fonts/OFL.txt
        icons/chevron.svg
        icons/warning.svg
        icons/error.svg
        icons/info.svg
        "${CYSEC_NOTICES_FILE}"
)

target_link_libraries(cysec_scanner_ui PUBLIC Qt6::Quick Qt6::QuickControls2 Qt6::Network)

target_compile_definitions(cysec_scanner_ui PUBLIC
    CYSEC_SCANNER_GUI_VERSION="${CYSEC_SCANNER_GUI_VERSION}")
