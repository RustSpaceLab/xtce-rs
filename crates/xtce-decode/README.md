# xtce-decode

Decodes CCSDS space packets against an XTCE definition, and is tested the only way that means
anything: packet for packet against
[`lasp/space_packet_parser`](https://github.com/lasp/space_packet_parser), the Python
implementation, over nine recorded mission streams. Where the two disagree, this crate is wrong
until proven otherwise — and the handful of deliberate divergences are listed, with reasons, in
the repository's `SUPPORTED.md`.

Measured at roughly 100× that reference on decode.

* **No panics.** Every failure is a `DecodeError`; a corrupt or hostile packet must not take
  down a process sitting on a live downlink.
* **No allocation for aligned reads.** Byte-aligned binary and string fields borrow straight
  from the packet.
* **Raw and engineering values both kept.** XTCE treats them as distinct and restriction
  criteria may test either.

Part of [RustSpaceLab/xtce-rs](https://github.com/RustSpaceLab/xtce-rs).
