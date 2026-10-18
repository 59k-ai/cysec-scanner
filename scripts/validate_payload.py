#!/usr/bin/env python3
"""Round-trip gate: prove the engine's --payload-out file is a strict-valid v5
payload the REAL cysec-collector Pydantic model accepts (PAY-04).

This is the auditable Go <-> Pydantic wire contract check, adapted from the
spike-005 validate.py. It is dependency-light (stdlib + the collector's own
pydantic, which the collector repo already vendors) and takes the collector repo
path as an argument so it is not pinned to one checkout.

Usage:
    python scripts/validate_payload.py <payload.json> <collector-repo-path>

It exits 0 and prints an "OK" line with schema_version=5 when the payload
validates, the schema_version is 5, and a model_dump_json -> model_validate_json
round-trip re-validates. Any ValidationError, a wrong schema_version, or a
missing argument exits non-zero.
"""

import pathlib
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(
            "usage: validate_payload.py <payload.json> <collector-repo-path>",
            file=sys.stderr,
        )
        return 2

    payload_path = pathlib.Path(argv[1])
    collector_repo = pathlib.Path(argv[2]).resolve()
    if not payload_path.is_file():
        print(f"payload file not found: {payload_path}", file=sys.stderr)
        return 2
    if not collector_repo.is_dir():
        print(f"collector repo path not a directory: {collector_repo}", file=sys.stderr)
        return 2

    # Import the collector's own source of truth from its repo checkout.
    sys.path.insert(0, str(collector_repo))
    from cysec_collector.payload import PAYLOAD_SCHEMA_VERSION, Payload

    raw = payload_path.read_text(encoding="utf-8")

    # First validation: the engine output must satisfy the strict model.
    pl = Payload.model_validate_json(raw)
    assert pl.schema_version == 5, (pl.schema_version, "expected 5")
    assert pl.schema_version == PAYLOAD_SCHEMA_VERSION, (
        pl.schema_version,
        PAYLOAD_SCHEMA_VERSION,
    )

    # Round-trip: re-serialize via Pydantic and confirm it still validates.
    again = Payload.model_validate_json(pl.model_dump_json())
    assert again.schema_version == 5, (again.schema_version, "expected 5")

    print(
        f"OK: Payload.model_validate_json accepted the engine output "
        f"schema_version={pl.schema_version} assets={len(pl.assets)} "
        f"identities={len(pl.identities)} service_exposures={len(pl.service_exposures)} "
        f"vulnerabilities={len(pl.vulnerabilities)} "
        f"configuration_checks={len(pl.configuration_checks)} "
        f"password_policies={len(pl.password_policies)} "
        f"software_inventory={len(pl.software_inventory)} "
        f"missing_kbs={len(pl.missing_kbs)} tls_probes={len(pl.tls_probes)}"
    )
    print("OK: round-trip re-validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
