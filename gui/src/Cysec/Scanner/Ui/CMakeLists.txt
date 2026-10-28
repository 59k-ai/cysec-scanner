# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Cysec.Scanner.Ui: the reusable STATIC QML module. STATIC means qmlcachegen
# compiles everything in and consumers deploy no separate plugin; they link
# cysec_scanner_uiplugin and Q_IMPORT_QML_PLUGIN(Cysec_Scanner_UiPlugin).

set_source_files_properties(Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(cysec_scanner_ui
    URI Cysec.Scanner.Ui
    VERSION 1.0
    STATIC
    QML_FILES
        Theme.qml
        PlainLabel.qml
)

target_link_libraries(cysec_scanner_ui PUBLIC Qt6::Quick Qt6::QuickControls2 Qt6::Network)

target_compile_definitions(cysec_scanner_ui PUBLIC
    CYSEC_SCANNER_GUI_VERSION="${CYSEC_SCANNER_GUI_VERSION}")
