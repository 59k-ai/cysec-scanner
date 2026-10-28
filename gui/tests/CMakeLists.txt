# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# GUI tests. tst_ui runs every tests/qml/tst_*.qml through Qt Quick Test.
# C++ unit tests are picked up from a fixed list when their source file
# exists, so later work adds a test by adding cpp/tst_<name>.cpp only.

find_package(Qt6 6.8 REQUIRED COMPONENTS Test)

# Optional fake engine used by process-level tests.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fakeengine/CMakeLists.txt")
    add_subdirectory(fakeengine)
endif()

qt_add_executable(tst_ui tst_main.cpp)
target_link_libraries(tst_ui PRIVATE Qt6::QuickTest Qt6::Quick cysec_scanner_uiplugin cysec_scanner_ui)
# tst_main.cpp builds HostModel/LogModel fixtures for the QML tests.
target_include_directories(tst_ui PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../src/Cysec/Scanner/Ui")
target_compile_definitions(tst_ui PRIVATE
    QUICK_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/qml"
    CYSEC_GUI_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
set_target_properties(tst_ui PROPERTIES MACOSX_BUNDLE OFF WIN32_EXECUTABLE OFF)
add_test(NAME tst_ui COMMAND tst_ui -platform offscreen)

function(cysec_gui_cpp_test name)
    set(_src "${CMAKE_CURRENT_SOURCE_DIR}/cpp/tst_${name}.cpp")
    if(NOT EXISTS "${_src}")
        return()
    endif()
    qt_add_executable(tst_${name} "${_src}")
    set_target_properties(tst_${name} PROPERTIES MACOSX_BUNDLE OFF WIN32_EXECUTABLE OFF)
    target_link_libraries(tst_${name} PRIVATE Qt6::Test Qt6::Quick cysec_scanner_ui)
    # The module target exports no include directory; C++ tests include its
    # headers by bare name ("ndjsonparser.h").
    target_include_directories(tst_${name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/Cysec/Scanner/Ui")
    target_compile_definitions(tst_${name} PRIVATE
        CYSEC_GUI_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    if(TARGET cysec-fake-engine)
        target_compile_definitions(tst_${name} PRIVATE
            CYSEC_FAKE_ENGINE_PATH="$<TARGET_FILE:cysec-fake-engine>")
        add_dependencies(tst_${name} cysec-fake-engine)
    endif()
    add_test(NAME tst_${name} COMMAND tst_${name} -platform offscreen)
endfunction()

foreach(_cysec_test IN ITEMS
        ndjsonparser processbackend hostmodel logmodel validators formatter
        exporter engineinfo language session real_engine)
    cysec_gui_cpp_test(${_cysec_test})
endforeach()

# macOS: the app bundle must be signed so Local Network privacy can match the
# user's decision (UAT 13 step 3). Only meaningful when the app is built.
if(APPLE AND TARGET cysec-scanner-gui)
    cysec_gui_cpp_test(macbundle)
    if(TARGET tst_macbundle)
        target_compile_definitions(tst_macbundle PRIVATE
            CYSEC_GUI_BUNDLE_DIR="$<TARGET_BUNDLE_DIR:cysec-scanner-gui>"
            CYSEC_GUI_BUNDLE_ID="$<TARGET_PROPERTY:cysec-scanner-gui,MACOSX_BUNDLE_GUI_IDENTIFIER>")
        add_dependencies(tst_macbundle cysec-scanner-gui)
    endif()
endif()

# tst_language builds a one-string catalogue at runtime to prove the
# translator swap without depending on the shipped .ts content.
if(TARGET tst_language AND TARGET Qt6::lrelease)
    target_compile_definitions(tst_language PRIVATE
        CYSEC_LRELEASE_PATH="$<TARGET_FILE:Qt6::lrelease>")
endif()
