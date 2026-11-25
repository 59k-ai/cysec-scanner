#!/usr/bin/env python3
# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
"""Trim what macdeployqt over-deploys into the macOS app bundle.

    prune-bundle.py <app> <qmlimportscanner-json>

macdeployqt copies far more than the GUI imports: every SQL driver (whose
ODBC/PostgreSQL/Mimer plugins link libraries outside the bundle), Qt
Multimedia with FFmpeg, the virtual keyboard and QML modules nobody imports.
That doubles the download and makes the bundle depend on whatever the build
machine had installed. This keeps exactly the QML modules qmlimportscanner
resolved for gui/app + gui/src (optional style imports included, so Controls
styles stay), drops the plugin families the app never loads, and then
removes every framework or dylib no remaining Mach-O links to. Runs before
signing, so nothing signed is touched afterwards.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Plugin families the GUI never loads (no QtSql, no media, no on-screen
# keyboard on desktop macOS).
UNUSED_PLUGIN_DIRS = ("sqldrivers", "multimedia", "platforminputcontexts")


def macho_deps(path: Path) -> list[str]:
    out = subprocess.run(["otool", "-L", str(path)], capture_output=True, text=True, check=True)
    return [line.split()[0] for line in out.stdout.splitlines() if line.startswith("\t")]


def is_macho(path: Path) -> bool:
    out = subprocess.run(["file", "-b", str(path)], capture_output=True, text=True, check=True)
    return "Mach-O" in out.stdout


def main() -> int:
    app = Path(sys.argv[1])
    scan = json.loads(Path(sys.argv[2]).read_text())
    contents = app / "Contents"
    qml_root = contents / "Resources" / "qml"
    plugins = contents / "PlugIns"
    frameworks = contents / "Frameworks"

    keep = {e["name"] for e in scan if e.get("type") == "module" and "name" in e}

    for name in UNUSED_PLUGIN_DIRS:
        shutil.rmtree(plugins / name, ignore_errors=True)

    # QML modules: drop a module directory unless it, or a module below it,
    # is kept. Deepest first, so a parent goes only after its children.
    modules = []
    for qmldir in qml_root.rglob("qmldir"):
        m = re.search(r"^module\s+(\S+)", qmldir.read_text(), re.M)
        if m:
            modules.append((qmldir.parent, m.group(1)))
    for directory, name in sorted(modules, key=lambda t: -len(t[0].parts)):
        if name in keep or any(k.startswith(name + ".") for k in keep):
            continue
        if directory.exists():
            print(f"prune QML {name}")
            shutil.rmtree(directory)

    # QML plugin binaries live in PlugIns/quick behind symlinks from the
    # module directories; drop the ones no surviving module points at.
    linked = {
        os.path.realpath(p) for p in qml_root.rglob("*") if p.is_symlink()
    }
    quick = plugins / "quick"
    if quick.is_dir():
        for lib in quick.iterdir():
            if os.path.realpath(lib) not in linked:
                print(f"prune plugin quick/{lib.name}")
                lib.unlink()

    # Frameworks and loose dylibs: keep the link closure of the executables
    # in Contents/MacOS and every remaining plugin.
    roots = [p for p in (contents / "MacOS").iterdir() if p.is_file() and is_macho(p)]
    roots += [p for p in plugins.rglob("*.dylib") if p.is_file()]
    needed: set[str] = set()
    queue = list(roots)
    seen: set[Path] = set()
    while queue:
        binary = queue.pop()
        if binary in seen:
            continue
        seen.add(binary)
        for dep in macho_deps(binary):
            m = re.match(r"@(?:rpath|executable_path/\.\./Frameworks|loader_path(?:/\.\.)*/Frameworks)/([^/]+)", dep)
            if not m:
                continue
            entry = m.group(1)
            if entry in needed:
                continue
            needed.add(entry)
            target = frameworks / entry
            if entry.endswith(".framework"):
                target = target / entry[: -len(".framework")]
            if target.exists():
                queue.append(target)
    for entry in sorted(frameworks.iterdir()):
        if entry.name not in needed:
            print(f"prune Frameworks/{entry.name}")
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
    return 0


if __name__ == "__main__":
    sys.exit(main())
