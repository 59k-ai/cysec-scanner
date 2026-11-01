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
        target_compile_definitions(tst_macbundle PRIVATE
            CYSEC_GUI_PROVISIONING_PROFILE_SET=$<BOOL:${CYSEC_GUI_PROVISIONING_PROFILE}>)
    endif()

    # The optional topology-observation signing path (MACs without
    # administrator rights) must refuse unusable input before it touches a
    # bundle: a restricted entitlement without a profile, an ad-hoc identity or
    # an unfilled template would produce an engine macOS kills at launch.
    set(_cysec_sign "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/macos-sign-bundle.cmake")
    set(_cysec_fx "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/macsign")
    set(_cysec_base -DBUNDLE=/nonexistent/x.app -DMAIN=x -DIDENTIFIER=ai.59k.cysec-scanner-gui)
    add_test(NAME macsign_entitlements_need_profile
        COMMAND "${CMAKE_COMMAND}" ${_cysec_base} -DIDENTITY=ABCDEF
            "-DENTITLEMENTS=${_cysec_fx}/filled.entitlements" -P "${_cysec_sign}")
    set_tests_properties(macsign_entitlements_need_profile PROPERTIES
        PASS_REGULAR_EXPRESSION "CYSEC_GUI_PROVISIONING_PROFILE")
    add_test(NAME macsign_profile_needs_entitlements
        COMMAND "${CMAKE_COMMAND}" ${_cysec_base} -DIDENTITY=ABCDEF
            "-DPROFILE=${_cysec_fx}/not-a-profile.provisionprofile" -P "${_cysec_sign}")
    set_tests_properties(macsign_profile_needs_entitlements PROPERTIES
        PASS_REGULAR_EXPRESSION "CYSEC_GUI_ENGINE_ENTITLEMENTS")
    add_test(NAME macsign_entitlements_need_real_identity
        COMMAND "${CMAKE_COMMAND}" ${_cysec_base} -DIDENTITY=-
            "-DENTITLEMENTS=${_cysec_fx}/filled.entitlements"
            "-DPROFILE=${_cysec_fx}/not-a-profile.provisionprofile" -P "${_cysec_sign}")
    set_tests_properties(macsign_entitlements_need_real_identity PROPERTIES
        PASS_REGULAR_EXPRESSION "Apple[ \n]+Development[ \n]+or[ \n]+Developer[ \n]+ID")
    add_test(NAME macsign_entitlements_reject_template
        COMMAND "${CMAKE_COMMAND}" ${_cysec_base} -DIDENTITY=ABCDEF
            "-DENTITLEMENTS=${CMAKE_CURRENT_SOURCE_DIR}/../app/macos/engine-topology-observation.entitlements.example"
            "-DPROFILE=${_cysec_fx}/not-a-profile.provisionprofile" -P "${_cysec_sign}")
    set_tests_properties(macsign_entitlements_reject_template PROPERTIES
        PASS_REGULAR_EXPRESSION "TEAMID")
    add_test(NAME macsign_profile_must_decode
        COMMAND "${CMAKE_COMMAND}" ${_cysec_base} -DIDENTITY=ABCDEF
            "-DENTITLEMENTS=${_cysec_fx}/filled.entitlements"
            "-DPROFILE=${_cysec_fx}/not-a-profile.provisionprofile" -P "${_cysec_sign}")
    set_tests_properties(macsign_profile_must_decode PROPERTIES
        PASS_REGULAR_EXPRESSION "cannot decode the provisioning profile")
endif()

# tst_language builds a one-string catalogue at runtime to prove the
# translator swap without depending on the shipped .ts content.
if(TARGET tst_language AND TARGET Qt6::lrelease)
    target_compile_definitions(tst_language PRIVATE
        CYSEC_LRELEASE_PATH="$<TARGET_FILE:Qt6::lrelease>")
endif()
