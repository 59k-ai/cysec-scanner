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
target_link_libraries(tst_ui PRIVATE Qt6::QuickTest Qt6::Quick cysec_scanner_uiplugin)
target_compile_definitions(tst_ui PRIVATE
    QUICK_TEST_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/qml")
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
        ndjsonparser processbackend hostmodel logmodel validators
        exporter engineinfo language session real_engine)
    cysec_gui_cpp_test(${_cysec_test})
endforeach()
