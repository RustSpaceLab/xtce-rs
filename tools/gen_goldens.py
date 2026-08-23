#!/usr/bin/env python3
"""Generate golden reference files from the Python `space_packet_parser` implementation.

The goldens are the ground truth for `cargo xtask diff`. They are committed to the
repository so CI never needs a Python interpreter.

Two encodings appear here, for two different jobs.

**JSON detail** — human-readable, for the first `--detail` packets. Values are encoded
losslessly:

    int            -> JSON integer
    bool           -> JSON boolean
    float          -> {"f": "<16 lowercase hex digits of the IEEE-754 bit pattern>"}
    str            -> JSON string
    bytes          -> {"b": "<lowercase hex>"}
    None           -> null

Floats are stored as their bit pattern rather than as `float.hex()` or a decimal literal
because the bit pattern is the only representation that is both exactly lossless and
trivially reproducible in another language. NaN and the infinities need no special case.

**Canonical digest** — a SHA-256 over *every* packet in the stream, so a mismatch in the
tail cannot hide behind the truncated detail section. The digest is taken over a
length-prefixed byte encoding defined below rather than over JSON, because reproducing
`json.dumps`'s exact output byte for byte (key order, `ensure_ascii` escaping, float
formatting) in another implementation is a trap. The encoding here has one obvious reading:

    blob(x)      = ascii(len(x)) b":" x
    value        = b"n"                        None
                 | b"B" b"0"|b"1"              bool
                 | b"i" blob(ascii(decimal))   int
                 | b"f" 16 hex bytes           float
                 | b"s" blob(utf8)             str
                 | b"b" blob(raw bytes)        bytes
    packet       = concat over names sorted by code point:
                       blob(utf8 name) value(raw) value(eng)
    stream       = concat over packets: blob(packet)

Usage:
    tools/gen_goldens.py [--detail 64] [--only jpss_geolocation]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
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

#: Marker recorded for a packet the reference itself refuses to decode.
UNRECOGNIZED = "__unrecognized__"


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
    # The only case whose packets were not flown. No mission definition in reach sets
    # `byteOrder`, so there is no recorded telemetry with a little-endian field in it, and
    # without bytes there is nothing to put in front of the reference. The stream is written
    # by `tools/gen_byte_order_stream.py` from a fixed seed. One packet in four carries an
    # APID the definition does not describe, so the refusal path is covered too.
    Case(
        name="byte_order",
        xtce="byte_order.xml",
        packets="byte_order_stream.bin",
    ),
    # A definition pointed at a stream it does not describe. Every packet reaches the
    # abstract root and finds no inheritor whose restriction criteria hold, so the reference
    # raises UnrecognizedPacketTypeError for all of them. Without this case the rejection
    # path is never exercised on either side: the five above have no unrecognised packets at
    # all, so the "we agree that this packet cannot be decoded" half of the contract would
    # go untested.
    Case(
        name="jpss_definition_over_ctim_stream",
        xtce="jpss/jpss1_geolocation_xtce_v1.xml",
        packets="ctim/ccsds_2021_155_14_39_51",
    ),
)


def float_bits(value: float) -> str:
    """The IEEE-754 bit pattern of `value` as 16 lowercase hex digits."""
    return f"{struct.unpack('<Q', struct.pack('<d', value))[0]:016x}"


def encode_json(value: Any) -> Any:
    """Encode a value from the reference parser into lossless JSON."""
    # bool before int: bool is a subclass of int. Note that the parser's own BoolParameter
    # subclasses int, not bool, so it lands in the int branch — matching what the reference
    # actually stores.
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return {"f": float_bits(value)}
    if isinstance(value, str):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return {"b": bytes(value).hex()}
    raise TypeError(f"unencodable value of type {type(value)!r}: {value!r}")


def blob(payload: bytes) -> bytes:
    return str(len(payload)).encode("ascii") + b":" + payload


def encode_canonical(value: Any) -> bytes:
    """Encode a value into the digest's canonical byte form."""
    if value is None:
        return b"n"
    if isinstance(value, bool):
        return b"B1" if value else b"B0"
    if isinstance(value, int):
        return b"i" + blob(str(int(value)).encode("ascii"))
    if isinstance(value, float):
        return b"f" + float_bits(value).encode("ascii")
    if isinstance(value, str):
        return b"s" + blob(str(value).encode("utf-8"))
    if isinstance(value, (bytes, bytearray)):
        return b"b" + blob(bytes(value))
    raise TypeError(f"unencodable value of type {type(value)!r}: {value!r}")


def encode_packet(packet: Any) -> dict[str, list[Any]]:
    """Encode one parsed packet as {parameter_name: [raw, eng]}."""
    out: dict[str, list[Any]] = {}
    for name, param in packet.items():
        raw = getattr(param, "raw_value", None)
        # The parser's parameter classes *are* their engineering value.
        out[str(name)] = [encode_json(raw), encode_json(param)]
    return out


def canonical_packet(packet: Any) -> bytes:
    """Canonical bytes for one packet, for the digest."""
    if packet is UNRECOGNIZED:
        return b"!"
    parts = []
    for name in sorted(packet.keys()):
        param = packet[name]
        raw = getattr(param, "raw_value", None)
        parts.append(blob(str(name).encode("utf-8")))
        parts.append(encode_canonical(raw))
        parts.append(encode_canonical(param))
    return b"".join(parts)


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
                parsed = pkt_def.parse_bytes(raw_bytes, **kwargs)
            except UnrecognizedPacketTypeError:
                # The reference itself rejects some packets: no inheritor satisfies the
                # restriction criteria. That rejection is part of the contract, so it is
                # recorded rather than skipped — our decoder must reject them too.
                parsed = UNRECOGNIZED
                errors += 1
            digest.update(blob(canonical_packet(parsed)))
            if count < detail:
                detail_packets.append(
                    {UNRECOGNIZED: True} if parsed is UNRECOGNIZED else encode_packet(parsed)
                )
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
            f"    {result['packet_count']} packets "
            f"({result['unrecognized_count']} unrecognized), "
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

    # Merge rather than replace. A `--only` run used to rewrite this file with the one case
    # it regenerated, silently dropping the timings for every other — which are the baseline
    # `cargo bench` reports against, and which cannot be recovered without rerunning
    # everything on the same machine.
    timings = args.out / "reference_timings.json"
    existing: list[dict[str, Any]] = []
    if timings.exists():
        existing = json.loads(timings.read_text())
    regenerated = {entry["case"] for entry in summary}
    merged = [entry for entry in existing if entry["case"] not in regenerated] + summary
    merged.sort(key=lambda entry: entry["case"])
    timings.write_text(json.dumps(merged, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
