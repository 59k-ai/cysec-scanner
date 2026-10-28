# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# POST_BUILD step for the macOS app bundle (cmake -P).
#
# Why: macOS Local Network privacy stores the user's Allow/Deny per code
# signing identifier and attributes the engine child to the app that spawned
# it. The linker's ad-hoc signature names the bare executable and leaves
# Info.plist unbound, so the stored decision never matches and every LAN
# peer except the gateway and the Mac itself answers "no route to host"
# (UAT 13 step 3). Signing the bundle with its CFBundleIdentifier fixes the
# match; the engine is signed first because nested code must be signed
# before the bundle that seals it.
#
# Inputs (-D):
#   BUNDLE      absolute path of the .app
#   MAIN        file name of the main executable in Contents/MacOS
#   IDENTIFIER  CFBundleIdentifier, used as the signing identifier
#   IDENTITY    codesign identity; "-" is ad-hoc, empty skips signing
#   ENGINE      optional engine binary to copy in as Contents/MacOS/cysec-scanner

if(NOT BUNDLE OR NOT MAIN OR NOT IDENTIFIER)
    message(FATAL_ERROR "macos-sign-bundle: BUNDLE, MAIN and IDENTIFIER are required")
endif()

set(_macos "${BUNDLE}/Contents/MacOS")

if(ENGINE)
    if(NOT EXISTS "${ENGINE}")
        message(FATAL_ERROR "macos-sign-bundle: CYSEC_GUI_BUNDLE_ENGINE does not exist: ${ENGINE}")
    endif()
    file(COPY_FILE "${ENGINE}" "${_macos}/cysec-scanner")
    file(CHMOD "${_macos}/cysec-scanner"
         PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
                     WORLD_READ WORLD_EXECUTE)
endif()

if("${IDENTITY}" STREQUAL "")
    return()
endif()

function(_cysec_codesign path identifier)
    execute_process(
        COMMAND /usr/bin/codesign --force --sign "${IDENTITY}" --identifier "${identifier}" "${path}"
        RESULT_VARIABLE _rc
        ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR "codesign failed for ${path}: ${_err}")
    endif()
endfunction()

# Nested executables (the bundled engine) first.
file(GLOB _nested LIST_DIRECTORIES false "${_macos}/*")
foreach(_file IN LISTS _nested)
    get_filename_component(_name "${_file}" NAME)
    if(NOT _name STREQUAL MAIN)
        _cysec_codesign("${_file}" "${IDENTIFIER}.${_name}")
    endif()
endforeach()

_cysec_codesign("${BUNDLE}" "${IDENTIFIER}")
