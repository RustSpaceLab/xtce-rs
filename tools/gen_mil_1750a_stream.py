#!/usr/bin/env python3
"""Write the packet stream `mil_1750a.xml` describes.

The second generated stream here, for the same reason as the first: no mission definition in
reach uses MIL-STD-1750A, so there is no recorded telemetry with one of its words in it, and
without bytes there is nothing to put in front of the reference implementation.

Deterministic — `xorshift64*` from a fixed seed — so regenerating produces the same file and
the golden over it stays meaningful. Rerun with:

    python3 tools/gen_mil_1750a_stream.py

Nothing in the bodies has to be fixed up, which is worth saying because the byte-order stream
does. Every one of the 2^32 MIL-STD-1750A words denotes a finite number: the format has no
infinities and no NaN, so there is no encoding whose value the two implementations could
disagree about the *kind* of. The IEEE-754 control field can be a NaN, and that is fine —
CPython's `struct` preserves a binary32 NaN payload, unlike a binary16 one.

One packet in four carries an APID the definition does not describe, so both implementations
have to refuse the same packets as well as decode the same ones.
"""

from __future__ import annotations

import struct
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "testdata" / "spp" / "mil_1750a_stream.bin"

#: A 48-bit primary header and 168 bits of body.
PACKET_BYTES = (48 + 168) // 8
#: CCSDS: the field counts the bytes after the primary header, less one.
PKT_LEN = PACKET_BYTES - 7
#: The APID the definition describes.
APID = 200

PACKETS = 512
SEED = 0x2545_F491_4F6C_DD1D


def xorshift(state: int) -> int:
    """`xorshift64*`, the same generator the Rust tests use."""
    state ^= state >> 12
    state &= 0xFFFF_FFFF_FFFF_FFFF
    state ^= (state << 25) & 0xFFFF_FFFF_FFFF_FFFF
    state ^= state >> 27
    return state


def main() -> int:
    state = SEED
    out = bytearray()

    for index in range(PACKETS):
        apid = APID if index % 4 else APID + 1
        header = bytearray(6)
        header[0] = (apid >> 8) & 0x07
        header[1] = apid & 0xFF
        header[2] = 0xC0 | ((index >> 8) & 0x3F)
        header[3] = index & 0xFF
        header[4:6] = struct.pack(">H", PKT_LEN)

        body = bytearray()
        while len(body) < PACKET_BYTES - 6:
            state = xorshift(state)
            body += struct.pack(">Q", (state * SEED) & 0xFFFF_FFFF_FFFF_FFFF)
        out += header + body[: PACKET_BYTES - 6]

    OUT.write_bytes(bytes(out))
    print(f"wrote {OUT.relative_to(REPO_ROOT)}: {PACKETS} packets, {len(out)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
