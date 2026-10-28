# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# The standalone app. The executable is deliberately NOT named cysec-scanner:
# the engine binary of that name ships next to it.

qt_add_executable(cysec-scanner-gui main.cpp)

set_target_properties(cysec-scanner-gui PROPERTIES
    WIN32_EXECUTABLE ON
    MACOSX_BUNDLE ON
    MACOSX_BUNDLE_BUNDLE_NAME "Cysec Scanner"
    MACOSX_BUNDLE_GUI_IDENTIFIER "ai.59k.cysec-scanner-gui"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}")

qt_add_qml_module(cysec-scanner-gui
    URI Cysec.Scanner.App
    VERSION 1.0
    QML_FILES Main.qml
    DEPENDENCIES Cysec.Scanner.Ui
)

target_link_libraries(cysec-scanner-gui PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
    cysec_scanner_uiplugin
    # The backing library carries the public compile definitions (GUI
    # version) and the C++ types; the plugin target does not forward them.
    cysec_scanner_ui)
