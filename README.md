# cysec-scanner

A pure-Go, cross-platform, open-source network scanner engine that discovers the
network and reads service/OS and Windows/AD posture, emitting a structured
network-evidence payload consumed by a compatible collector. Published under the
Apache License 2.0 as the auditable engine behind a thin closed collector wrapper.

## MAC addresses on macOS

The engine reads MAC addresses (and from them the vendor) from the operating
system's neighbour (ARP) cache after the host sweep. On Linux that is
`/proc/net/arp`, on Windows `arp -a`; both are readable without extra rights.

macOS 27 hides the IPv4 neighbour cache from processes that run without
administrator rights: `arp -an` prints nothing, and the routing sysctl returns
no neighbour entries (IPv6 neighbours and even the Mac's own interface show the
placeholder `02:00:00:00:00:00`). Local Network permission does not change
this. `--describe` then reports `"arp_cache": false`, and every
`mac_address` / `mac_vendor` stays `null`. The rest of the scan (hosts, ports,
names, OS guesses) is unaffected.

To get MAC addresses and vendors on macOS 27, run the command-line engine with
administrator rights:

```sh
sudo cysec-scanner --cidr 192.168.1.0/24 --payload-out scan.json
```

The engine stays read-only under `sudo`: it only reads the cache the kernel
already holds (`arp -an`) and opens no listening socket. Hosts whose MAC is
randomized ("private Wi-Fi address", locally administered) have a MAC but no
vendor, because such addresses are not registered with the IEEE.

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

`cysec-scanner` versions via **git tags** and the `go.mod` module path; release
tooling derives build-time version info from the git tag / commit. There is no
in-tree version constant to bump.
