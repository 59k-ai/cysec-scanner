# Third-Party Notices

`cysec-scanner` is licensed under the Apache License, Version 2.0 (see
[`LICENSE`](./LICENSE)). This file satisfies the Apache-2.0 `NOTICE`
obligation by recording the licenses and required attributions of every
third-party dataset bundled into the binary and every third-party Go-module
dependency.

The dataset allowlist at [`data/allowlist.json`](./data/allowlist.json) is the
single machine-readable source of truth for which data files are embedded,
their SHA-256 pins, their licenses, and their provenance. The human-readable
notices below MUST stay consistent with that manifest.

Dataset notices are emitted in a deterministic, stable order — sorted by the
dataset's embedded data path (the `path` field in `data/allowlist.json`) — so
regenerating this file never reorders existing entries. Each distinct dataset
is listed separately even when two datasets share a license, so no required
attribution is silently dropped by de-duplication.

## Bundled Datasets

### IEEE OUI Public Listing (MA-L / MA-M / MA-S)

- **Source:** https://standards-oui.ieee.org/
- **Data paths:** `data/oui/oui.csv` (MA-L), `data/oui/mam.csv` (MA-M), `data/oui/oui36.csv` (MA-S)
- **License:** `NOASSERTION` — IEEE non-assertion of copyright
- **Redistribution sign-off:** [`data/oui/SIGNOFF.md`](./data/oui/SIGNOFF.md) (LIC-04)

The IEEE OUI MAC-vendor snapshot (all three registry blocks MA-L, MA-M and
MA-S) is redistributed under IEEE's published non-assertion of copyright. The
IEEE Registration Authority states verbatim:

> IEEE does not assert any copyright in the OUI Public Listing or attempt to
> restrict distribution of the listing in any way. The IEEE Registration
> Authority does, however, strongly encourage those who use the list to obtain
> it directly from IEEE (and to update it on a regular basis) to ensure the
> integrity of the information.

Redistribution is therefore permitted and there is no mandatory attribution
clause — only a non-binding encouragement to obtain the list directly from
IEEE. This attribution is provided as a courtesy, not a license obligation.
The pinned snapshot, its per-file SHA-256, the registry-block metadata, and the
human-recorded redistribution sign-off are maintained in
[`data/allowlist.json`](./data/allowlist.json) and
[`data/oui/SIGNOFF.md`](./data/oui/SIGNOFF.md).

### Recog service fingerprints (Rapid7)

- **Source:** https://github.com/rapid7/recog
- **Data paths:** `data/recog/ssh_banners.xml`, `data/recog/http_servers.xml`, `data/recog/ftp_banners.xml`, `data/recog/smtp_banners.xml`, `data/recog/telnet_banners.xml`, `data/recog/pop_banners.xml`, `data/recog/imap_banners.xml`
- **License:** BSD-2-Clause

All vendored Recog files are fetched from the same pinned upstream commit
(`data/allowlist.json` → `upstream_snapshot`), so the whole corpus shares one
provenance id.

BSD-2-Clause requires retaining the copyright notice, the list of conditions,
and the disclaimer below in redistributions:

```
Copyright (c) 2014-2015, Rapid7

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Go-Module Dependencies

This repository currently has no third-party Go runtime dependencies at this
phase; the module graph is effectively stdlib-only (see `go.mod`). This section
is therefore complete and correct for the empty-dependency case, not silently
missing.

As engine code and its dependencies land in later phases, the per-dependency
notices gathered by `go-licenses save ./... --save_path=...` will be appended
here so that every third-party Go module that ships in the binary carries its
required notice.

## GUI Assets

The optional desktop GUI under [`gui/`](./gui/) bundles the assets below into
its QML module. They are not part of the Go engine binary.

### IBM Plex Sans and IBM Plex Mono fonts

- **Source:** https://github.com/IBM/plex (release tags `@ibm/plex-sans@1.1.0`
  and `@ibm/plex-mono@1.1.0`, `fonts/complete/ttf/` from each release zip,
  unmodified)
- **Path:** `gui/src/Cysec/Scanner/Ui/fonts/`
- **License:** SIL Open Font License 1.1 (`OFL-1.1`); full text shipped as
  [`gui/src/Cysec/Scanner/Ui/fonts/OFL.txt`](./gui/src/Cysec/Scanner/Ui/fonts/OFL.txt)
  and embedded in the GUI next to the fonts
- **Copyright:** Copyright © 2017 IBM Corp. with Reserved Font Name "Plex"

| File | Release | SHA-256 |
|------|---------|---------|
| `IBMPlexSans-Regular.ttf` | `@ibm/plex-sans@1.1.0` | `975dcda37d80f038dcd143c22e33ca2d97a0cc5a929aace1c749153b0fe1afa5` |
| `IBMPlexSans-SemiBold.ttf` | `@ibm/plex-sans@1.1.0` | `a20caf8286023a6a7a85e40b1d2a4ae9fc3e3b1f9eda8f4c542dd4986af67bb1` |
| `IBMPlexMono-Regular.ttf` | `@ibm/plex-mono@1.1.0` | `fe11304a5fe956d5744e9b6a246cc83d90425245e75a62230044966ca96a7f50` |
| `IBMPlexMono-SemiBold.ttf` | `@ibm/plex-mono@1.1.0` | `c9417148ce13f8fa7d2d5c9180bbc141f72aa0d814ffeb280f6904dc2b1bbd7a` |

### Qt 6

- **Source:** https://download.qt.io/ (complete corresponding source for every
  Qt release)
- **License:** GNU Lesser General Public License v3 (`LGPL-3.0-only`)

The GUI uses Qt under the LGPLv3 and links it dynamically: the Qt libraries
ship as separate shared libraries / frameworks next to the executable. You may
replace them with your own modified build of the same Qt version and relink;
the Qt source is available from download.qt.io, and the GUI source is in this
repository.

### GUI icons

- **Path:** `gui/src/Cysec/Scanner/Ui/icons/`
- **License:** Apache-2.0 (original work of 59k GmbH, same license as this
  repository)
