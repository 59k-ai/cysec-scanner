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

# main.cpp builds the session, the process backend and EngineInfo; the module
# target exports no include directory, so the app includes its headers by
# bare name like the C++ tests do.
target_include_directories(cysec-scanner-gui PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/Cysec/Scanner/Ui")

# macOS: Local Network privacy (UAT 13 step 3). The scanner must reach other
# hosts on the LAN, which macOS gates per app and attributes to the app that
# spawned the engine. The bundle therefore explains the access in its
# Info.plist and is signed as a bundle, with its CFBundleIdentifier as the
# signing identifier, so the user's Allow decision actually matches it. The
# linker's own ad-hoc signature does neither. See cmake/macos-sign-bundle.cmake.
if(APPLE)
    set(CYSEC_GUI_CODESIGN_IDENTITY "-" CACHE STRING
        "codesign identity for the app bundle; '-' is ad-hoc, empty skips signing")
    set(CYSEC_GUI_BUNDLE_ENGINE "" CACHE FILEPATH
        "engine binary copied into the bundle as Contents/MacOS/cysec-scanner before signing")
    # Optional, default off: sign the bundled engine with the restricted
    # topology-observation entitlement so it can read neighbour MACs on macOS
    # 27 without administrator rights. Needs both, plus a real identity.
    set(CYSEC_GUI_ENGINE_ENTITLEMENTS "" CACHE FILEPATH
        "entitlements plist for the bundled engine (see app/macos/engine-topology-observation.entitlements.example)")
    set(CYSEC_GUI_PROVISIONING_PROFILE "" CACHE FILEPATH
        "provisioning profile granting the topology-observation entitlement, embedded in the bundle")

    set_target_properties(cysec-scanner-gui PROPERTIES
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/macos/Info.plist.in")
    set(_cysec_de_strings "${CMAKE_CURRENT_SOURCE_DIR}/macos/de.lproj/InfoPlist.strings")
    target_sources(cysec-scanner-gui PRIVATE "${_cysec_de_strings}")
    set_source_files_properties("${_cysec_de_strings}" PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources/de.lproj")

    add_custom_command(TARGET cysec-scanner-gui POST_BUILD
        COMMAND "${CMAKE_COMMAND}"
            "-DBUNDLE=$<TARGET_BUNDLE_DIR:cysec-scanner-gui>"
            "-DMAIN=$<TARGET_FILE_NAME:cysec-scanner-gui>"
            "-DIDENTIFIER=$<TARGET_PROPERTY:cysec-scanner-gui,MACOSX_BUNDLE_GUI_IDENTIFIER>"
            "-DIDENTITY=${CYSEC_GUI_CODESIGN_IDENTITY}"
            "-DENGINE=${CYSEC_GUI_BUNDLE_ENGINE}"
            "-DENTITLEMENTS=${CYSEC_GUI_ENGINE_ENTITLEMENTS}"
            "-DPROFILE=${CYSEC_GUI_PROVISIONING_PROFILE}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/macos-sign-bundle.cmake"
        VERBATIM)
endif()
