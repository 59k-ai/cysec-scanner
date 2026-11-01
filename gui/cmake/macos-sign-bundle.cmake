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
#   ENTITLEMENTS  optional entitlements plist for the engine and the bundle
#   PROFILE       optional provisioning profile, embedded as
#                 Contents/embedded.provisionprofile
#
# ENTITLEMENTS + PROFILE (both or neither) carry the restricted
# com.apple.developer.networking.topology-observation entitlement, which lets
# the engine read neighbour MAC addresses on macOS 27 without administrator
# rights. The engine reads the cache itself, so the engine carries it, signed
# with the bundle identifier so its application-identifier matches the
# profile's App ID. A restricted entitlement without a matching profile makes
# macOS kill the process at launch, so the input is checked first. Untested
# end to end: see gui/README.md.

if(NOT BUNDLE OR NOT MAIN OR NOT IDENTIFIER)
    message(FATAL_ERROR "macos-sign-bundle: BUNDLE, MAIN and IDENTIFIER are required")
endif()

set(_topology_key "com.apple.developer.networking.topology-observation")
set(_plistbuddy /usr/libexec/PlistBuddy)

function(_cysec_plist_get file key out)
    execute_process(COMMAND "${_plistbuddy}" -c "Print :${key}" "${file}"
        OUTPUT_VARIABLE _v RESULT_VARIABLE _rc ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT _rc EQUAL 0)
        set(_v "")
    endif()
    set(${out} "${_v}" PARENT_SCOPE)
endfunction()

if(ENTITLEMENTS OR PROFILE)
    if(NOT ENTITLEMENTS)
        message(FATAL_ERROR "macos-sign-bundle: CYSEC_GUI_PROVISIONING_PROFILE needs "
                            "CYSEC_GUI_ENGINE_ENTITLEMENTS as well")
    endif()
    if(NOT PROFILE)
        message(FATAL_ERROR "macos-sign-bundle: CYSEC_GUI_ENGINE_ENTITLEMENTS needs "
                            "CYSEC_GUI_PROVISIONING_PROFILE as well (a restricted entitlement "
                            "without a profile is killed at launch)")
    endif()
    if("${IDENTITY}" STREQUAL "" OR "${IDENTITY}" STREQUAL "-")
        message(FATAL_ERROR "macos-sign-bundle: the topology-observation entitlement needs an "
                            "Apple Development or Developer ID identity in "
                            "CYSEC_GUI_CODESIGN_IDENTITY, not ad-hoc or unsigned")
    endif()
    foreach(_f IN ITEMS "${ENTITLEMENTS}" "${PROFILE}")
        if(NOT EXISTS "${_f}")
            message(FATAL_ERROR "macos-sign-bundle: file does not exist: ${_f}")
        endif()
    endforeach()
    file(READ "${ENTITLEMENTS}" _ent_text)
    if(_ent_text MATCHES "TEAMID")
        message(FATAL_ERROR "macos-sign-bundle: replace the TEAMID placeholder in ${ENTITLEMENTS} "
                            "with your Apple team ID")
    endif()

    string(RANDOM LENGTH 12 _rnd)
    set(_tmp "$ENV{TMPDIR}")
    if(NOT _tmp)
        set(_tmp /tmp)
    endif()
    set(_decoded "${_tmp}/cysec-profile-${_rnd}.plist")
    execute_process(COMMAND /usr/bin/security cms -D -i "${PROFILE}" -o "${_decoded}"
        RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_QUIET)
    if(NOT _rc EQUAL 0 OR NOT EXISTS "${_decoded}")
        file(REMOVE "${_decoded}")
        message(FATAL_ERROR "macos-sign-bundle: cannot decode the provisioning profile ${PROFILE}")
    endif()
    _cysec_plist_get("${_decoded}" "Entitlements:${_topology_key}" _granted)
    _cysec_plist_get("${_decoded}" "Entitlements:com.apple.application-identifier" _profile_app)
    file(REMOVE "${_decoded}")
    _cysec_plist_get("${ENTITLEMENTS}" "com.apple.application-identifier" _ent_app)
    if(NOT _granted STREQUAL "true")
        message(FATAL_ERROR "macos-sign-bundle: the provisioning profile does not grant ${_topology_key}")
    endif()
    if(NOT _ent_app STREQUAL _profile_app)
        message(FATAL_ERROR "macos-sign-bundle: entitlements application-identifier '${_ent_app}' "
                            "does not match the profile's '${_profile_app}'")
    endif()
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

if(PROFILE)
    file(COPY_FILE "${PROFILE}" "${BUNDLE}/Contents/embedded.provisionprofile")
endif()

# Optional extra arguments (e.g. --entitlements file) after the identifier.
function(_cysec_codesign path identifier)
    execute_process(
        COMMAND /usr/bin/codesign --force --sign "${IDENTITY}" --identifier "${identifier}"
                ${ARGN} "${path}"
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
    if(ENTITLEMENTS AND _name STREQUAL "cysec-scanner")
        # The engine reads the neighbour cache, so it holds the entitlement,
        # under the App ID the profile was issued for.
        _cysec_codesign("${_file}" "${IDENTIFIER}" --entitlements "${ENTITLEMENTS}")
    elseif(NOT _name STREQUAL MAIN)
        _cysec_codesign("${_file}" "${IDENTIFIER}.${_name}")
    endif()
endforeach()

if(ENTITLEMENTS)
    _cysec_codesign("${BUNDLE}" "${IDENTIFIER}" --entitlements "${ENTITLEMENTS}")
else()
    _cysec_codesign("${BUNDLE}" "${IDENTIFIER}")
endif()
