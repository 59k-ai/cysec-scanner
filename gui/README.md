# Cysec Scanner GUI

A native Qt Quick desktop front end for the `cysec-scanner` engine. It runs
the engine as a child process, shows hosts as they are found, and exports the
results as JSON or CSV. Nothing leaves the machine.

The directory is a standalone CMake project with two parts:

- **`Cysec.Scanner.Ui`** (`src/Cysec/Scanner/Ui/`): a reusable STATIC QML
  module with the theme singleton and the base controls. Other Qt
  applications can consume it without the app.
- **`cysec-scanner-gui`** (`app/`): the standalone application. The engine
  binary `cysec-scanner` ships next to it.

## Qt version policy

- **API floor: Qt 6.8.** The code uses no Qt API newer than 6.8, and
  `find_package(Qt6 6.8)` / `qt_standard_project_setup(REQUIRES 6.8)` enforce
  the minimum.
- **Release builds:** Qt 6.12 on macOS, Linux and Windows. CI also builds
  and tests against Qt 6.8.3 on Linux to keep the floor honest.
- Local development works with any Qt from 6.8 upwards.

## Build

```sh
# Point CMAKE_PREFIX_PATH at your Qt kit, e.g. ~/Qt/6.12.0/macos
cmake -S gui -B gui/build -G Ninja -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/macos"
cmake --build gui/build
```

Module only (no app, no tests), as another project would consume it:

```sh
cmake -S gui -B gui/build-lib -G Ninja -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/macos" \
      -DCYSEC_GUI_BUILD_APP=OFF -DCYSEC_GUI_BUILD_TESTS=OFF
cmake --build gui/build-lib
```

Build directories (`gui/build*/`) are ignored by git.

## Run during development

Build the engine from the repository root, then point the GUI at it with the
`CYSEC_SCANNER_BIN` override (release builds only look next to the GUI
executable):

```sh
GOWORK=off go build -o gui/build/cysec-scanner ./cmd/cysec-scanner
CYSEC_SCANNER_BIN="$PWD/gui/build/cysec-scanner" \
    gui/build/app/cysec-scanner-gui.app/Contents/MacOS/cysec-scanner-gui   # macOS
# Linux: gui/build/app/cysec-scanner-gui   Windows: gui\build\app\cysec-scanner-gui.exe
```

### macOS: Local Network privacy

macOS decides per app whether it may reach other hosts on the local network,
and it charges the engine to the app that started it. Without that permission
every host except the router and the Mac itself answers "no route to host",
and a scan finds almost nothing. A scan run from Terminal is not affected,
which is why the CLI and the app can disagree.

The build therefore signs the bundle after linking, with the bundle identifier
as the signing identifier (`cmake/macos-sign-bundle.cmake`), and the
Info.plist explains the access. To ship the engine inside the bundle, which is
how the app finds it without `CYSEC_SCANNER_BIN`, configure with:

```sh
cmake -S gui -B gui/build -DCYSEC_GUI_BUNDLE_ENGINE="$PWD/gui/build/cysec-scanner"
```

`CYSEC_GUI_CODESIGN_IDENTITY` defaults to `-` (ad-hoc). Set it to an Apple
Development or Developer ID identity for the most reliable behaviour, or to
an empty string to leave signing to a packaging step. Every relink changes
the executable, so macOS can refuse the very first launch of a fresh build.
If a scan straight after a rebuild finds only the router and this Mac, quit
the app and start it again. The setting is under System Settings > Privacy &
Security > Local Network.

### macOS: MAC addresses and vendors

macOS 27 shows the MAC addresses of other devices only to programs that run
with administrator rights; Local Network permission does not include them.
The app does not ask for those rights, so on macOS the MAC address and MAC
vendor columns read "Hidden by macOS" and the detail panel says "Not
available on macOS without administrator rights" for hosts without a MAC.
Linux and Windows are not affected.

Hosts that answer NetBIOS (usually Windows) still get a MAC: the engine takes
it from their NetBIOS node-status reply when the cache gives none. To see MAC
addresses and vendors for all hosts on macOS, run the command-line engine with
`sudo` (see the repository README, "MAC addresses on macOS"):

```sh
sudo gui/build/cysec-scanner --cidr 192.168.1.0/24 --payload-out scan.json
```

### macOS: MAC addresses without administrator rights (untested)

Apple grants neighbour MAC addresses on macOS 27 to programs that carry the
restricted entitlement `com.apple.developer.networking.topology-observation`
(Xcode capability "Network Topology Observation"). The engine reads the cache
itself through `sysctl` (`NET_RT_FLAGS_PRIV`), so the bundled engine must carry
the entitlement; a spawned `/usr/sbin/arp` would not inherit it. The build can
sign the engine that way. It is off by default, and the ad-hoc and plain Apple
Development builds are unchanged.

**This path has not been tested end to end**: it needs a provisioning profile
that grants the entitlement. In particular it is not yet confirmed that macOS
accepts the profile embedded in the app for the engine in `Contents/MacOS`.
If it does not, macOS kills the engine at launch ("Killed: 9", and Console
shows `taskgated` / AMFI rejecting the entitlement). The fallback then is to
ship the engine in its own app-like wrapper with its own profile, which needs
a change to where the GUI looks for the engine.

Steps in the Apple Developer portal (Certificates, Identifiers & Profiles),
for team `LZ9GFJBK99`:

1. **Identifiers:** register an explicit App ID for macOS with the bundle ID
   `ai.59k.cysec-scanner-gui`, or open the existing one.
2. On that App ID, enable **Network Topology Observation** (under
   Capabilities, or Additional Capabilities if Apple lists it as a request).
   Save.
3. **Devices:** for a development profile, register this Mac by its
   Provisioning UDID (System Information > Hardware).
4. **Profiles:** create a **macOS App Development** profile (for the Apple
   Development certificate; local testing) or a **Developer ID** profile (for
   distribution outside the App Store). Select the App ID above, the
   certificate that `CYSEC_GUI_CODESIGN_IDENTITY` names, and for development
   the Mac. Download the `.provisionprofile`.

Then, outside the repository:

```sh
cp gui/app/macos/engine-topology-observation.entitlements.example ~/cysec-engine.entitlements
# replace TEAMID with LZ9GFJBK99 (three places)
cmake -S gui -B gui/build \
    -DCYSEC_GUI_BUNDLE_ENGINE="$PWD/gui/build/cysec-scanner" \
    -DCYSEC_GUI_ENGINE_ENTITLEMENTS="$HOME/cysec-engine.entitlements" \
    -DCYSEC_GUI_PROVISIONING_PROFILE="$HOME/Downloads/<profile>.provisionprofile"
cmake --build gui/build
```

The signing step refuses to run with only one of the two settings, with an
ad-hoc identity, with the TEAMID placeholder left in, or with a profile that
does not grant the entitlement or names a different App ID. It embeds the
profile as `Contents/embedded.provisionprofile` and signs the engine (under
the bundle identifier) and the bundle with the entitlements.

To check the result:

```sh
codesign -d --entitlements - gui/build/app/cysec-scanner-gui.app/Contents/MacOS/cysec-scanner
gui/build/app/cysec-scanner-gui.app/Contents/MacOS/cysec-scanner --describe   # expect "arp_cache": true
```

Then scan from the app: the MAC address and MAC vendor columns should list
addresses and vendors instead of "Hidden by macOS". Distribution with Developer ID also needs the hardened
runtime, a timestamp and notarization; that is a packaging step outside this
build.

## Test

```sh
QT_QPA_PLATFORM=offscreen ctest --test-dir gui/build --output-on-failure
cmake --build gui/build --target all_qmllint
```

Test-only environment switches:

- `CYSEC_SCANNER_REDUCED_MOTION=1` turns all animations off.
- `CYSEC_SCANNER_FONT_SCALE=1.5` scales every font size (clamped to 1.0 to 2.0).

## Translations

English is the source language and German is translated. The catalogue lives
in `gui/i18n/`; refresh it with `cmake --build gui/build --target update_translations`.

## Licences

The GUI is Apache-2.0. Qt is used under LGPLv3 and linked dynamically. The
bundled IBM Plex fonts are under the SIL Open Font License 1.1. See
[`../THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
