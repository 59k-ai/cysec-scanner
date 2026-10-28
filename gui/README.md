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
