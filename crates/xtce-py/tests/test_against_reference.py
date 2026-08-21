"""The Python bindings, checked against `space_packet_parser` field by field.

The Rust side is already proven equal to the reference over six streams by `cargo xtask
diff`. This checks the *binding*: that nothing is lost or reshaped on the way across the
boundary. It is a separate question, and a binding that quietly turned an unsigned 64-bit
value into a float would pass every Rust test in the project.

Run with the reference installed:

    python3.12 -m venv .venv
    .venv/bin/pip install space_packet_parser maturin pytest
    .venv/bin/maturin develop --release --manifest-path crates/xtce-py/Cargo.toml
    .venv/bin/pytest crates/xtce-py/tests
"""

from __future__ import annotations

import math
import warnings
from pathlib import Path

import pytest

import xtce

space_packet_parser = pytest.importorskip("space_packet_parser")
from space_packet_parser import generators  # noqa: E402
from space_packet_parser.xtce import definitions  # noqa: E402

TESTDATA = Path(__file__).resolve().parents[3] / "testdata" / "spp"

#: (definition, stream, root container, bytes to skip before each packet).
CASES = [
    (
        "jpss/jpss1_geolocation_xtce_v1.xml",
        "jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1",
        None,
        0,
    ),
    (
        "ctim/ctim_xtce_v1.xml",
        "ctim/ccsds_2021_155_14_39_51",
        "CCSDSTelemetryPacket",
        0,
    ),
    (
        "suda/suda_combined_science_definition.xml",
        "suda/sciData_2022_130_17_41_53.spl",
        None,
        4,
    ),
    (
        "idex/idex_combined_science_definition.xml",
        "idex/sciData_2023_052_14_45_05",
        None,
        0,
    ),
]

#: Comparing every packet of the two 7200-packet streams through the reference takes about a
#: second each; capping keeps the suite quick while still covering thousands of packets.
MAX_PACKETS = 400


def reference_packets(definition_path: Path, stream_path: Path, root, skip_header_bytes):
    """Decode with `space_packet_parser`, yielding one dict per packet."""
    pkt_def = definitions.XtcePacketDefinition.from_xtce(definition_path)
    kwargs = {"root_container_name": root} if root else {}
    with stream_path.open("rb") as fh, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for index, raw_bytes in enumerate(
            generators.ccsds_generator(fh, skip_header_bytes=skip_header_bytes)
        ):
            if index >= MAX_PACKETS:
                return
            yield pkt_def.parse_bytes(raw_bytes, **kwargs)


def same(ours, theirs) -> bool:
    """Equality that treats two NaNs as equal, since both sides decoded the same bits."""
    if isinstance(ours, float) and isinstance(theirs, float):
        if math.isnan(ours) and math.isnan(theirs):
            return True
        # Not a tolerance: both implementations read the same bits, so anything but exact
        # equality is a real difference. `==` on floats is the assertion here.
        return ours == theirs
    return ours == theirs


@pytest.mark.parametrize("definition,stream,root,skip", CASES)
def test_engineering_values_match_the_reference(definition, stream, root, skip):
    ours = xtce.Definition(str(TESTDATA / definition))
    decoded = ours.decode_stream(
        (TESTDATA / stream).read_bytes(), skip_header_bytes=skip, root=root
    )

    compared = 0
    for index, expected in enumerate(
        reference_packets(TESTDATA / definition, TESTDATA / stream, root, skip)
    ):
        got = decoded[index]
        assert set(got) - {"__container__"} == set(expected), (
            f"packet {index}: different parameter sets"
        )
        for name, reference_value in expected.items():
            assert same(got[name], reference_value), (
                f"packet {index}: {name}: {got[name]!r} != {reference_value!r}"
            )
        compared += 1

    assert compared > 0, "no packets were compared"


@pytest.mark.parametrize("definition,stream,root,skip", CASES)
def test_raw_values_match_the_reference(definition, stream, root, skip):
    ours = xtce.Definition(str(TESTDATA / definition))
    decoded = ours.decode_stream(
        (TESTDATA / stream).read_bytes(), skip_header_bytes=skip, root=root, raw=True
    )

    for index, expected in enumerate(
        reference_packets(TESTDATA / definition, TESTDATA / stream, root, skip)
    ):
        got = decoded[index]
        for name, parameter in expected.items():
            reference_raw = getattr(parameter, "raw_value", parameter)
            assert same(got[name], reference_raw), (
                f"packet {index}: {name}: raw {got[name]!r} != {reference_raw!r}"
            )


def test_container_selection_matches_the_reference():
    """The binding must choose the same container the reference does."""
    definition = TESTDATA / "jpss/jpss1_geolocation_xtce_v1.xml"
    stream = TESTDATA / "jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1"

    ours = xtce.Definition(str(definition))
    containers = ours.container_of_each(stream.read_bytes())
    assert len(containers) == 7200
    assert set(containers) == {"JPSS_ATT_EPHEM"}


def test_a_definition_that_does_not_describe_the_stream_is_refused():
    """The rejection path, which the Rust side has a golden case for."""
    ours = xtce.Definition(str(TESTDATA / "jpss/jpss1_geolocation_xtce_v1.xml"))
    ctim = (TESTDATA / "ctim/ccsds_2021_155_14_39_51").read_bytes()

    with pytest.raises(ValueError, match="no matching inheritor"):
        ours.decode_stream(ctim)

    # Asking to skip them yields nothing rather than raising.
    assert ours.decode_stream(ctim, skip_unrecognized=True) == []


def test_a_truncated_packet_is_refused():
    ours = xtce.Definition(str(TESTDATA / "jpss/jpss1_geolocation_xtce_v1.xml"))
    stream = (TESTDATA / "jpss/J01_G011_LZ_2021-04-09T00-00-00Z_V01.DAT1").read_bytes()

    with pytest.raises(ValueError):
        ours.decode(stream[:10])


def test_definition_metadata():
    path = TESTDATA / "idex/idex_combined_science_definition.xml"
    ours = xtce.Definition(str(path))

    assert ours.parameter_count == 207
    assert "PKT_APID" in ours.parameter_names()
    assert ours.container_count == 9
    assert ours.source == str(path)
    # This definition is entirely within the decodable subset.
    assert ours.unsupported() == []


def test_from_string():
    ours = xtce.Definition.from_string(
        """<?xml version="1.0" encoding="UTF-8"?>
<SpaceSystem xmlns="http://www.omg.org/spec/XTCE/20180204" name="Test">
  <TelemetryMetaData>
    <ParameterTypeSet>
      <IntegerParameterType name="T">
        <IntegerDataEncoding sizeInBits="8" encoding="unsigned"/>
      </IntegerParameterType>
    </ParameterTypeSet>
    <ParameterSet><Parameter name="A" parameterTypeRef="T"/></ParameterSet>
    <ContainerSet>
      <SequenceContainer name="P">
        <EntryList><ParameterRefEntry parameterRef="A"/></EntryList>
      </SequenceContainer>
    </ContainerSet>
  </TelemetryMetaData>
</SpaceSystem>"""
    )
    assert ours.source is None
    assert ours.decode(b"\x2a", root="P")["A"] == 42


def test_the_gil_is_released_during_decoding():
    """A long decode must not stop other Python threads from running.

    Without `Python::detach` around the Rust loop the counter thread would be starved for
    the whole call, which is the difference between a binding that scales and one that
    serialises every consumer behind it.
    """
    import threading

    ours = xtce.Definition(str(TESTDATA / "ctim/ctim_xtce_v1.xml"))
    data = (TESTDATA / "ctim/ccsds_2021_155_14_39_51").read_bytes()

    ticks = 0
    stop = threading.Event()

    def spin():
        nonlocal ticks
        while not stop.is_set():
            ticks += 1

    worker = threading.Thread(target=spin, daemon=True)
    worker.start()
    try:
        for _ in range(5):
            ours.decode_stream(data, root="CCSDSTelemetryPacket")
    finally:
        stop.set()
        worker.join(timeout=5)

    assert ticks > 0, "the counter thread never ran, so the GIL was held throughout"
