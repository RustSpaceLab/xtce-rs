# xtce-decode

[![crates.io](https://img.shields.io/crates/v/xtce-decode.svg)](https://crates.io/crates/xtce-decode)
[![docs.rs](https://docs.rs/xtce-decode/badge.svg)](https://docs.rs/xtce-decode)

Decodes CCSDS space packets against an XTCE definition, and is tested the only way that means
anything: packet for packet against
[`lasp/space_packet_parser`](https://github.com/lasp/space_packet_parser), the Python
implementation, over nine recorded mission streams. Where the two disagree, this crate is wrong
until proven otherwise — and the handful of deliberate divergences are listed, with reasons, in
the repository's `SUPPORTED.md`.

Measured at roughly 100× that reference on decode.

* **No panics.** Every failure is a `DecodeError`; a corrupt or hostile packet must not take
  down a process sitting on a live downlink.
* **Constant-memory streaming.** `PacketReader` frames CCSDS packets sequentially from any
  `std::io::Read` source into a single reusable buffer ($\le 64\text{ KiB}$).
* **No allocation for aligned reads.** Byte-aligned binary and string fields borrow straight
  from the packet.
* **Raw and engineering values both kept.** XTCE treats them as distinct and restriction
  criteria may test either.

## Example

```rust,no_run
use std::fs::File;
use std::io::BufReader;
use xtce_decode::{Decoder, PacketReader};
use xtce_model::XtceDb;

let db = XtceDb::from_path("mission.xml")?;
let decoder = Decoder::new(&db)?;

let file = File::open("downlink.bin")?;
let mut reader = PacketReader::new(BufReader::new(file), 0);
while let Some(framed) = reader.next_packet()? {
    let packet = decoder.decode(framed.bytes())?;
    for (name, val) in packet.iter_named() {
        println!("{name} = {} (raw {})", val.eng, val.raw);
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
