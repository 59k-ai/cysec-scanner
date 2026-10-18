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

## Bundled Datasets

### Recog service fingerprints (Rapid7)

- **Source:** https://github.com/rapid7/recog
- **License:** BSD-2-Clause
- **Files:** `data/recog/*.xml`

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

### IEEE OUI Public Listing (MA-L / MA-M / MA-S)

_Added in a later plan (01-03)._ The IEEE OUI MAC-vendor snapshot is
redistributed under IEEE's published non-assertion of copyright ("IEEE does
not assert any copyright in the OUI Public Listing or attempt to restrict
distribution of the listing in any way"). Attribution is provided as a
courtesy; the pinned snapshot, its SHA-256, and the one-line redistribution
sign-off land with plan 01-03.

## Go-Module Dependencies

_Added in a later plan._ This repository currently vendors no runtime
third-party Go modules; the dependency notices gathered by `go-licenses save`
will be recorded here as engine code and its dependencies land (plan 01-02 and
Phase 2+).
