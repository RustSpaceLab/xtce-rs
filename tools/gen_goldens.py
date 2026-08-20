#!/usr/bin/env python3
"""Generate golden reference files from the Python `space_packet_parser` implementation.

The goldens are the ground truth for the differential tests in `xtask diff`. They are
committed to the repository so CI never needs a Python interpreter.

Value encoding (lossless, JSON-representable):

    int            -> JSON integer
    bool           -> JSON boolean
    float          -> {"f": "<float.hex()>"}   exact IEEE-754 round-trip
    str            -> JSON string
    bytes          -> {"b": "<lowercase hex>"}
    None           -> null

Each golden file holds full detail for the first `--detail` packets plus a SHA-256
digest over the canonical encoding of *every* packet in the stream, so a truncated
detail section can never hide a mismatch in the tail.

Usage:
    tools/gen_goldens.py --out testdata/golden [--detail 64]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from space_packet_parser import generators
from space_packet_parser.exceptions import UnrecognizedPacketTypeError
from space_packet_parser.xtce import definitions

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTDATA = REPO_ROOT / "testdata" / "spp"


@dataclass(frozen=True)
class Case:
    """One (definition, packet stream) pair to be decoded."""

    name: str
    xtce: str
    packets: str
    root_container: str | None = None
    skip_header_bytes: int = 0


CASES: tuple[Case, ...] = (
    Case(
        name="jpss_geolocation",
        xtce="jpss/jpss1_geolocation_xtce_v1.xml",
        packets="jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1",
    ),
    Case(
        name="jpss_contrived_inheritance",
        xtce="jpss/contrived_inheritance_structure.xml",
        packets="jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1",
    ),
    Case(
        name="ctim",
        xtce="ctim/ctim_xtce_v1.xml",
        packets="ctim/ccsds_2021_155_14_39_51",
        root_container="CCSDSTelemetryPacket",
    ),
    Case(
        name="suda",
        xtce="suda/suda_combined_science_definition.xml",
        packets="suda/sciData_2022_130_17_41_53.spl",
        skip_header_bytes=4,
    ),
    Case(
        name="idex",
        xtce="idex/idex_combined_science_definition.xml",
        packets="idex/sciData_2023_052_14_45_05",
    ),
)


def encode(value: Any) -> Any:
    """Encode a Python value from the reference parser into lossless JSON."""
    # bool before int: bool is a subclass of int.
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return {"f": float(value).hex()}
    if isinstance(value, str):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return {"b": bytes(value).hex()}
    raise TypeError(f"unencodable value of type {type(value)!r}: {value!r}")


def encode_packet(packet: Any) -> dict[str, list[Any]]:
    """Encode one parsed packet as {parameter_name: [raw, eng]}."""
    out: dict[str, list[Any]] = {}
    for name, param in packet.items():
        raw = getattr(param, "raw_value", None)
        # `_Parameter` subclasses *are* their engineering value.
        out[str(name)] = [encode(raw), encode(param)]
    return out


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def iter_packets(case: Case) -> Iterator[bytes]:
    with (TESTDATA / case.packets).open("rb") as fh:
        yield from generators.ccsds_generator(fh, skip_header_bytes=case.skip_header_bytes)


def run_case(case: Case, detail: int) -> dict[str, Any]:
    xtce_path = TESTDATA / case.xtce

    load_start = time.perf_counter()
    pkt_def = definitions.XtcePacketDefinition.from_xtce(xtce_path)
    load_seconds = time.perf_counter() - load_start

    kwargs = {"root_container_name": case.root_container} if case.root_container else {}

    detail_packets: list[Any] = []
    digest = hashlib.sha256()
    count = 0
    errors = 0

    parse_start = time.perf_counter()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for raw_bytes in iter_packets(case):
            try:
                encoded: Any = encode_packet(pkt_def.parse_bytes(raw_bytes, **kwargs))
            except UnrecognizedPacketTypeError:
                # The reference itself rejects some packets (no inheritor satisfies the
                # restriction criteria). That rejection is part of the contract, so it is
                # recorded rather than skipped — our decoder must reject them too.
                encoded = {"__unrecognized__": True}
                errors += 1
            digest.update(canonical(encoded))
            digest.update(b"\x1e")  # record separator: keeps concatenation unambiguous
            if count < detail:
                detail_packets.append(encoded)
            count += 1
    parse_seconds = time.perf_counter() - parse_start

    return {
        "case": case.name,
        "xtce": case.xtce,
        "packets": case.packets,
        "root_container": case.root_container,
        "skip_header_bytes": case.skip_header_bytes,
        "packet_count": count,
        "unrecognized_count": errors,
        "detail_count": len(detail_packets),
        "digest_sha256": digest.hexdigest(),
        "reference": {
            "implementation": "lasp/space_packet_parser",
            "load_seconds": round(load_seconds, 6),
            "parse_seconds": round(parse_seconds, 6),
        },
        "detail": detail_packets,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "testdata" / "golden")
    ap.add_argument("--detail", type=int, default=64, help="packets stored in full detail")
    ap.add_argument("--only", action="append", help="restrict to named case(s)")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    selected = [c for c in CASES if not args.only or c.name in args.only]

    summary = []
    for case in selected:
        print(f"==> {case.name}", flush=True)
        result = run_case(case, args.detail)
        dest = args.out / f"{case.name}.json"
        dest.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
        ref = result["reference"]
        print(
            f"    {result['packet_count']} packets, "
            f"load {ref['load_seconds']:.3f}s, parse {ref['parse_seconds']:.3f}s "
            f"-> {dest.relative_to(REPO_ROOT)}",
            flush=True,
        )
        summary.append(
            {
                "case": case.name,
                "packet_count": result["packet_count"],
                "load_seconds": ref["load_seconds"],
                "parse_seconds": ref["parse_seconds"],
            }
        )

    (args.out / "reference_timings.json").write_text(json.dumps(summary, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
