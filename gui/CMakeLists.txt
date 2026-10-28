# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Cysec Scanner GUI: a reusable STATIC QML module (Cysec.Scanner.Ui) plus a
# standalone app (cysec-scanner-gui) and its tests.
#
# Qt API floor is 6.8: nothing here may use a Qt API introduced after 6.8,
# even though local dev and CI build against newer releases. Consumers that
# only want the module configure with CYSEC_GUI_BUILD_APP=OFF and
# CYSEC_GUI_BUILD_TESTS=OFF and link cysec_scanner_uiplugin.

cmake_minimum_required(VERSION 3.21)

project(cysec_scanner_gui VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.8 REQUIRED COMPONENTS
    Core Gui Qml Quick QuickControls2 Network LinguistTools QuickTest)

qt_standard_project_setup(REQUIRES 6.8
    I18N_SOURCE_LANGUAGE en
    I18N_TRANSLATED_LANGUAGES de)

# Every QML module lands under one import root that mirrors its URI, so
# qmllint, qmlls and the tests resolve Cysec.Scanner.Ui without extra paths.
set(QT_QML_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/qml")

option(CYSEC_GUI_BUILD_APP   "Build the standalone cysec-scanner-gui app" ${PROJECT_IS_TOP_LEVEL})
option(CYSEC_GUI_BUILD_TESTS "Build the GUI tests"                       ${PROJECT_IS_TOP_LEVEL})

# One git tag versions the engine and the GUI together; outside a git
# checkout (source tarball) fall back to the CMake project version.
execute_process(
    COMMAND git describe --tags --always --dirty
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE CYSEC_SCANNER_GUI_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE _cysec_git_describe_result)
if(NOT _cysec_git_describe_result EQUAL 0 OR CYSEC_SCANNER_GUI_VERSION STREQUAL "")
    set(CYSEC_SCANNER_GUI_VERSION "${PROJECT_VERSION}")
endif()
message(STATUS "cysec-scanner GUI version: ${CYSEC_SCANNER_GUI_VERSION}")

add_subdirectory(src/Cysec/Scanner/Ui)

if(CYSEC_GUI_BUILD_APP)
    add_subdirectory(app)
endif()

if(CYSEC_GUI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Catalogue lives in gui/i18n; the update_translations target refreshes it.
# -locations none keeps the .ts files stable across unrelated edits.
qt_add_translations(TARGETS cysec_scanner_ui
    SOURCE_TARGETS cysec_scanner_ui
    TS_FILE_BASE cysec_scanner_ui
    TS_FILE_DIR i18n
    LUPDATE_OPTIONS -locations none)
