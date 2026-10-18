# cysec-scanner

A pure-Go, cross-platform, open-source network scanner engine that discovers the
network and reads service/OS and Windows/AD posture, emitting the cysec.watch
Collector payload. Published under the Apache License 2.0 as the auditable engine
behind a thin closed Collector wrapper.

## License

Apache-2.0. See [`LICENSE`](./LICENSE). The Apache `NOTICE` obligation is
satisfied by [`NOTICE`](./NOTICE), which points to
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

## Data governance

Every embedded data file under `data/` is recorded in the single source of truth
[`data/allowlist.json`](./data/allowlist.json) with its SHA-256, license, and
provenance. A `go:embed` integrity test (`internal/governance`) two-way-matches
the embedded filesystem against that manifest, a layered denylist blocks
contaminating (copyleft/OEM) datasets, and `cmd/datacheck` runs both gates as a
CI contract (GitHub Actions, `.github/workflows/governance.yml`).

## Versioning convention

Unlike the Python sub-repos in this workspace (`cysec-collector`, `cysecwatch`),
`cysec-scanner` is a **Go** module. It has **no `__version__.py`** and the
workspace Python version-bump-before-commit rule does **not** apply here. The
scanner versions via **git tags** and the `go.mod` module path; release tooling
derives build-time version info from the git tag / commit.
