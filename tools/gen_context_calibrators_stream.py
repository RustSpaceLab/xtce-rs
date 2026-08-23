#!/usr/bin/env python3
"""Write the packet stream `context_calibrators.xml` describes.

The third generated stream here, for the usual reason: no mission definition in reach has a
`<ContextCalibratorList>`, so there is no recorded telemetry that selects between calibrators
and nothing to put in front of the reference.

Deterministic — `xorshift64*` from a fixed seed. Rerun with:

    python3 tools/gen_context_calibrators_stream.py

Unlike the other two generated streams this one is *not* filled with arbitrary bytes, and the
reason is the whole point of the file. A context is chosen by a comparison, and a comparison
against a uniformly random field almost never holds: `MODE == 1` over a random byte is one
packet in 256, so 512 packets would exercise each branch twice and the default five hundred
times. The fields the criteria test are therefore drawn from small ranges, chosen so that
every branch of every chain is taken tens of times:

* MODE spans 0 to 4, so the three contexts that test it and the default all come up.
* SELF spans 0 to 2047, straddling the 1000 its own criterion compares against.
* LOOKAHEAD spans 0 to 10. Its criterion names LATER, which is decoded after it and so
  resolves to LOOKAHEAD's own raw value — the surprising case, and one that would go
  untested if LOOKAHEAD were a uniform 16-bit number that never equalled 5.

Everything not named in a criterion stays arbitrary.

One packet in four carries an APID the definition does not describe, so both implementations
have to refuse the same packets as well as decode the same ones.
"""

from __future__ import annotations

import struct
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "testdata" / "spp" / "context_calibrators_stream.bin"

#: A 48-bit primary header and 80 bits of body.
PACKET_BYTES = (48 + 80) // 8
PKT_LEN = PACKET_BYTES - 7
APID = 300

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
        body = body[: PACKET_BYTES - 6]

        body[0] = body[0] % 5  # MODE: 0 to 4
        body[3] = body[3] % 8  # SELF, high byte: 0 to 2047 all told
        body[5] = 0  # LOOKAHEAD, high byte
        body[6] = body[6] % 11  # LOOKAHEAD, low byte: 0 to 10

        out += header + body

    OUT.write_bytes(bytes(out))
    print(f"wrote {OUT.relative_to(REPO_ROOT)}: {PACKETS} packets, {len(out)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
