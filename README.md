# cysec-scanner

A pure-Go, cross-platform, open-source network scanner engine that discovers the
network and reads service/OS and Windows/AD posture, emitting a structured
network-evidence payload consumed by a compatible collector. Published under the
Apache License 2.0 as the auditable engine behind a thin closed collector wrapper.

## MAC addresses on macOS

The engine reads MAC addresses (and from them the vendor) from the operating
system's neighbour (ARP) cache after the host sweep. On Linux that is
`/proc/net/arp`, on Windows `arp -a`; both are readable without extra rights.

The scanning machine's own addresses are never in its own neighbour cache. For
a result that is one of the machine's own IPv4 addresses, the engine takes the
MAC from the interface that carries the address, read from the operating
system's interface list. This needs no extra rights and works on Linux, macOS
and Windows. Like a cache MAC, it sets the asset's `external_id` to
`mac:<mac>`, and `classification_evidence.evidence` records
`"mac_source": "local_interface"`. If the operating system reports a
placeholder instead of the real address (macOS can show `02:00:00:00:00:00`),
the address is ignored and the MAC stays `null`.

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
already holds (in-process `sysctl`, falling back to `arp -an`) and opens no
listening socket.

Without administrator rights, two other sources still apply:

- **NetBIOS:** when a host has no cache entry, the engine uses the unit ID from
  the NetBIOS node-status reply it already requests for the host name (Windows
  hosts report their adapter MAC there; Samba usually reports zeros, which are
  ignored). It is used only for hosts on a local segment, it does not change the
  asset's `external_id`, and the asset's `classification_evidence.evidence`
  records `"mac_source": "netbios_self_reported"`, because the host reports the
  value about itself.
- **Entitled build:** an engine signed with Apple's restricted
  `com.apple.developer.networking.topology-observation` entitlement reads the
  cache in-process through `sysctl` `NET_RT_FLAGS_PRIV`. See the GUI README
  (untested). Hosts whose MAC is
randomized ("private Wi-Fi address", locally administered) have a MAC but no
vendor, because such addresses are not registered with the IEEE.

## Install on Windows

Download from the
[GitHub Releases page](https://github.com/59k-ai/cysec-scanner/releases). Each
release has a `SHA256SUMS` file. To verify a download, run
`Get-FileHash -Algorithm SHA256 <file>` in PowerShell and compare the hash with
that file's line in `SHA256SUMS`. Both downloads are x64 only.

**MSI (recommended):** `cysec-scanner-<version>-windows-x64.msi`. It needs
administrator rights, installs for all users to `C:\Program Files\Cysec Scanner`
and adds a "Cysec Scanner" entry to the Start Menu. To uninstall, use
Settings → Apps. The installer is not code-signed yet, so SmartScreen shows
"Windows protected your PC". Click **More info → Run anyway** to continue.
Installing a newer release upgrades the existing one in place. Installing an
older release over a newer one is refused.

For IT deployment (GPO, Intune), install and uninstall silently from an elevated
prompt:

```bat
msiexec /i cysec-scanner-<version>-windows-x64.msi /qn
msiexec /x cysec-scanner-<version>-windows-x64.msi /qn
```

**Portable zip:** `cysec-scanner-<version>-windows-x64.zip` needs no
administrator rights. Extract it anywhere and run `cysec-scanner-gui.exe`.
Keep `cysec-scanner.exe` in the same folder, because the GUI only looks for the
engine next to itself. The zip includes the Qt and Visual C++ runtimes, so
nothing else has to be installed.

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
