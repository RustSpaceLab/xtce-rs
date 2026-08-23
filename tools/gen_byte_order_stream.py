#!/usr/bin/env python3
"""Write the packet stream `byte_order.xml` describes.

Every other stream under `testdata/spp` was flown. This one could not be: no mission
definition in reach sets `byteOrder` at all, so there is no recorded telemetry that exercises
a little-endian field, and without bytes there is nothing to put in front of the reference
implementation.

The stream is deterministic — `xorshift64*` from a fixed seed — so regenerating it produces
the same file, and a golden taken over it stays meaningful. Rerun with:

    python3 tools/gen_byte_order_stream.py

The bodies are arbitrary bit patterns on purpose. A little-endian field's value depends on
every byte of it, so a stream of round numbers would agree under a wrong implementation as
often as a right one; NaN payloads, subnormals and sign bits are where the two come apart.

One packet in four carries an APID the definition does not describe, so the *refusal* path is
exercised as well: both implementations have to reject the same packets, and a stream where
everything decodes leaves that half of the contract untested.
"""

from __future__ import annotations

import struct
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "testdata" / "spp" / "byte_order_stream.bin"

#: Total packet size the definition implies: a 48-bit primary header, SEL, and 400 bits of
#: body.
PACKET_BYTES = (48 + 16 + 400) // 8
#: CCSDS: the field counts the bytes after the primary header, less one.
PKT_LEN = PACKET_BYTES - 7
#: The APID the definition describes.
APID = 100
#: SEL as it must appear on the wire for the criterion to hold: 0x0102 reversed is 0x0201.
SEL_BYTES = bytes((0x01, 0x02))

#: Offset of F16_LE within the body, in bytes: the primary header is 6 and the field sits at
#: bit 248 of the packet.
HALF_AT = 248 // 8 - 6

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
        # Three packets in four are the described APID; the fourth is not, and both
        # implementations have to refuse it.
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
        body = body[: PACKET_BYTES - 6]
        # SEL is the first two bytes after the header, and has to satisfy the criterion for
        # the packets whose APID already does.
        body[0:2] = SEL_BYTES

        # F16_LE must not be a NaN. Not because NaN is uninteresting — it is one of the more
        # interesting things a float field can hold — but because the reference and this
        # project disagree about it, deliberately and on the record: CPython's `struct` loses
        # a binary16 NaN's payload while keeping a binary32 or binary64 one, and this project
        # keeps all three. `SUPPORTED.md` says so under deliberate divergences. Leaving NaNs
        # in the stream would turn a documented difference into a failing golden.
        #
        # The field is little-endian, so its value is the two bytes reversed. Turning a NaN
        # into an infinity keeps the extreme exponent, which is the part worth covering.
        low, high = body[HALF_AT], body[HALF_AT + 1]
        if (high >> 2) & 0x1F == 0x1F and ((high & 0x03) or low):
            body[HALF_AT] = 0
            body[HALF_AT + 1] = high & 0xFC

        out += header + body

    OUT.write_bytes(bytes(out))
    print(f"wrote {OUT.relative_to(REPO_ROOT)}: {PACKETS} packets, {len(out)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
