#!/usr/bin/env bash
# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# macOS release build: one self-contained, universal (arm64 + x86_64)
# "Cysec Scanner.app" with the scan engine inside, packaged as a .dmg.
#
#   packaging/macos/build-dmg.sh <tag> <qt-prefix> <outdir>
#
#   tag        release tag, stamped into the engine (v0.1.10)
#   qt-prefix  Qt for macOS install prefix (…/Qt/6.12.0/macos); the Qt
#              frameworks there must be universal, as the qt.io builds are
#   outdir     receives cysec-scanner-<tag>-macos-universal.dmg
#
# Used by .github/workflows/release.yml and runnable on a developer Mac.
#
# Layout: the GUI resolves the engine only next to its own executable
# (processscanbackend.cpp), so the engine ships as Contents/MacOS/cysec-scanner.
# macdeployqt copies the Qt frameworks, plugins and QML imports into the
# bundle and breaks the build-time signature, so the bundle is re-signed
# afterwards: nested code ad-hoc first, then the engine and the bundle with
# the bundle identifier through gui/cmake/macos-sign-bundle.cmake, because
# macOS Local Network privacy matches the user's Allow by that identifier.
#
# The signature is ad-hoc (no Apple Developer ID yet) and the dmg is not
# notarised, so Gatekeeper blocks the first launch of a downloaded copy:
# the user opens it via System Settings > Privacy & Security > Open Anyway.
# Developer ID signing + notarytool go where the ad-hoc identity is passed,
# once a certificate exists.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <tag> <qt-prefix> <outdir>" >&2
    exit 2
fi

tag="$1"
qt_prefix="$(cd "$2" && pwd)"
mkdir -p "$3"
outdir="$(cd "$3" && pwd)"

root="$(cd "$(dirname "$0")/../.." && pwd)"
identity="-"
deployment_target="13.0"
app_name="Cysec Scanner.app"
dmg="$outdir/cysec-scanner-$tag-macos-universal.dmg"

work="$(mktemp -d "${TMPDIR:-/tmp}/cysec-dmg.XXXXXX")"
# CYSEC_KEEP_WORK=1 keeps the build tree for inspection.
if [ "${CYSEC_KEEP_WORK:-0}" != 1 ]; then
    trap 'rm -rf "$work"' EXIT
fi

macdeployqt="$qt_prefix/bin/macdeployqt"
[ -x "$macdeployqt" ] || { echo "macdeployqt not found under $qt_prefix/bin" >&2; exit 1; }

echo "== engine (universal)"
for arch in arm64 amd64; do
    (cd "$root" && CGO_ENABLED=0 GOWORK=off GOOS=darwin GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w -X main.version=$tag" \
        -o "$work/engine-$arch" ./cmd/cysec-scanner)
done
lipo -create -output "$work/cysec-scanner" "$work/engine-arm64" "$work/engine-amd64"
lipo -archs "$work/cysec-scanner"

echo "== GUI (universal, Release)"
generator=()
if command -v ninja >/dev/null 2>&1; then
    generator=(-G Ninja)
fi
cmake -S "$root/gui" -B "$work/build" ${generator[@]+"${generator[@]}"} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$qt_prefix" \
    "-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$deployment_target" \
    -DCYSEC_GUI_BUILD_TESTS=OFF \
    -DCYSEC_GUI_CODESIGN_IDENTITY="$identity" \
    -DCYSEC_GUI_BUNDLE_ENGINE="$work/cysec-scanner"
cmake --build "$work/build" --config Release --target cysec-scanner-gui --parallel

built_app="$(find "$work/build" -maxdepth 3 -type d -name 'cysec-scanner-gui.app' | head -n 1)"
[ -n "$built_app" ] || { echo "cysec-scanner-gui.app not produced" >&2; exit 1; }

stage="$work/stage"
mkdir -p "$stage"
app="$stage/$app_name"
cp -R "$built_app" "$app"
main="$app/Contents/MacOS/cysec-scanner-gui"
identifier="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")"

echo "== macdeployqt"
"$macdeployqt" "$app" -qmldir="$root/gui/app" -qmldir="$root/gui/src" -always-overwrite

echo "== prune"
# macdeployqt over-deploys (SQL drivers linking outside libraries, Multimedia,
# virtual keyboard, unused QML modules); keep what the GUI imports.
"$qt_prefix/libexec/qmlimportscanner" -rootPath "$root/gui/app" -rootPath "$root/gui/src" \
    -importPath "$qt_prefix/qml" > "$work/qml-imports.json"
python3 -I "$root/packaging/macos/prune-bundle.py" "$app" "$work/qml-imports.json"

# The build tree's rpath into the Qt prefix must not survive: a machine that
# happens to have Qt at the same path would load that Qt instead of ours.
while read -r rpath; do
    case "$rpath" in
        "$qt_prefix"*|/Users/*|/opt/*|"$work"*)
            install_name_tool -delete_rpath "$rpath" "$main" ;;
    esac
done < <(otool -l "$main" | awk '/cmd LC_RPATH/{getline; getline; print $2}')

echo "== sign (ad-hoc, bundle identifier $identifier)"
# Inside out: dylibs/plugins, then frameworks, then the engine and bundle.
find "$app/Contents" -type f \( -name '*.dylib' -o -name '*.so' \) -print0 |
    xargs -0 -n 1 codesign --force --sign "$identity" >/dev/null
find "$app/Contents/Frameworks" -maxdepth 1 -type d -name '*.framework' -print0 |
    xargs -0 -n 1 codesign --force --sign "$identity" >/dev/null
cmake -DBUNDLE="$app" -DMAIN=cysec-scanner-gui -DIDENTIFIER="$identifier" \
    -DIDENTITY="$identity" -P "$root/gui/cmake/macos-sign-bundle.cmake"

echo "== gates"
codesign --verify --deep --strict --verbose=2 "$app"
got_id="$(codesign -dv "$app" 2>&1 | sed -n 's/^Identifier=//p')"
[ "$got_id" = "$identifier" ] || { echo "bundle signed as '$got_id', want '$identifier'" >&2; exit 1; }

for bin in "$main" "$app/Contents/MacOS/cysec-scanner" \
           "$app/Contents/Frameworks/QtCore.framework/Versions/A/QtCore"; do
    archs="$(lipo -archs "$bin")"
    case " $archs " in *" arm64 "*) ;; *) echo "$bin lacks arm64 ($archs)" >&2; exit 1 ;; esac
    case " $archs " in *" x86_64 "*) ;; *) echo "$bin lacks x86_64 ($archs)" >&2; exit 1 ;; esac
done

got="$("$app/Contents/MacOS/cysec-scanner" --version)"
echo "engine --version: $got"
[ "$got" = "$tag" ] || { echo "engine version '$got' does not equal $tag" >&2; exit 1; }

# Self-contained: every Mach-O links only system libraries or bundle-relative
# paths, and no rpath reaches outside the bundle.
bad=0
while IFS= read -r -d '' f; do
    file -b "$f" | grep -q 'Mach-O' || continue
    while read -r dep; do
        case "$dep" in
            @rpath/*|@executable_path/*|@loader_path/*|/usr/lib/*|/System/*) ;;
            *) echo "external dependency in ${f#"$app"/}: $dep" >&2; bad=1 ;;
        esac
    # Dependency lines are tab-indented; the others name the file (per arch).
    done < <(otool -L "$f" | awk '/^\t/{print $1}')
    while read -r rpath; do
        case "$rpath" in
            @executable_path/*|@loader_path/*) ;;
            *) echo "rpath outside the bundle in ${f#"$app"/}: $rpath" >&2; bad=1 ;;
        esac
    done < <(otool -l "$f" | awk '/cmd LC_RPATH/{getline; getline; print $2}')
done < <(find "$app/Contents" -type f \( -perm -u+x -o -name '*.dylib' -o -name '*.so' \) -print0)
[ "$bad" -eq 0 ] || exit 1

# The app must start from the bundle alone: Qt's own lookup is pointed away
# from the build prefix. A root QML that fails to load exits the app (main.cpp);
# a plugin or import that fails to load lazily shows up in the log.
QT_PLUGIN_PATH= QML_IMPORT_PATH= QML2_IMPORT_PATH= "$main" > "$work/startup.log" 2>&1 &
pid=$!
sleep 6
if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" || true
    cat "$work/startup.log" >&2
    echo "the app exited during startup" >&2
    exit 1
fi
kill "$pid"
wait "$pid" 2>/dev/null || true
cat "$work/startup.log"
if grep -Eiq 'is not installed|cannot load library|could not load the qt platform plugin|module .* not found' "$work/startup.log"; then
    echo "the app logged a missing module or plugin at startup" >&2
    exit 1
fi
echo "startup OK"

echo "== dmg"
ln -s /Applications "$stage/Applications"
for f in LICENSE NOTICE THIRD_PARTY_NOTICES.md README.md; do
    cp "$root/$f" "$stage/"
done
rm -f "$dmg"
hdiutil create -volname "Cysec Scanner $tag" -srcfolder "$stage" \
    -fs HFS+ -format UDZO -ov "$dmg" >/dev/null
hdiutil verify "$dmg" >/dev/null
ls -l "$dmg"
