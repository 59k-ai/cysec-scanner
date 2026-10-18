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
- **Data path:** `data/recog/ssh_banners.xml`
- **License:** BSD-2-Clause

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
