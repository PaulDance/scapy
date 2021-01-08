from scapy.fields import BitField, BitEnumField, BitFieldLenField, XStrLenField, \
    XIntField, XStrField, XStrFixedLenField, IntEnumField, FieldListField
from scapy.layers.quic.packets.common import CommonBehavior
from scapy.layers.quic.packets.fields import encode_length, QuicVarLenField
from scapy.layers.quic.packets.frames import FrameStorage

QUIC_HEADER_FORMS = {0: "Short", 1: "Long"}
QUIC_LONG_PACKET_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
MAX_PACKET_NUMBER_LEN = 4


class PacketNumberInterface(CommonBehavior):
    """
    Interface-like class adding methods common to all packet types containing
    a packet number field.
    """

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.length is None:
            pnl = len(self.packet_number)
            pkt = pkt[:-pnl - 1] + encode_length(len(pay) + pnl + 16) + pkt[-pnl:]

        return pkt + pay

    def get_packet_number_length(self) -> int:
        """
        :return: The packet number length's true value, i.e. `pnl + 1`.
        :rtype: int
        """
        return self.packet_number_length + 1


class QuicLongHeader(CommonBehavior):
    """
    Long Header Packet {
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2),
      Type-Specific Bits (4),
      Version (32),
      Destination Connection ID Length (8),
      Destination Connection ID (0..160),
      Source Connection ID Length (8),
      Source Connection ID (0..160),
    }
    """
    name = "QUIC Long Header"
    fields_desc = [
        BitEnumField("header_form", 1, 1, QUIC_HEADER_FORMS),
        BitEnumField("fixed_bit", 1, 1, {1: "1"}),
        BitEnumField("long_packet_type", None, 2, QUIC_LONG_PACKET_TYPES),
        BitField("type_specific_bits", None, 4),
        XIntField("version", None),
        BitFieldLenField(
            "destination_connection_id_length", None,
            8, length_of="destination_connection_id",
        ),
        XStrLenField(
            "destination_connection_id", b"", max_length=20,
            length_from=lambda pkt: pkt.destination_connection_id_length,
        ),
        BitFieldLenField(
            "source_connection_id_length", None,
            8, length_of="source_connection_id",
        ),
        XStrLenField(
            "source_connection_id", b"", max_length=20,
            length_from=lambda pkt: pkt.source_connection_id_length,
        ),
    ]


class Quic0Rtt(QuicLongHeader, PacketNumberInterface, FrameStorage):
    """
    0-RTT Packet {
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2) = 1,
      Reserved Bits (2),
      Packet Number Length (2),
      Version (32),
      Destination Connection ID Length (8),
      Destination Connection ID (0..160),
      Source Connection ID Length (8),
      Source Connection ID (0..160),
      Length (i),
      Packet Number (8..32),
      Packet Payload (..),
    }
    """
    name = "QUIC 0-RTT"
    fields_desc = QuicLongHeader.fields_desc.copy()
    fields_desc[2] = BitEnumField("long_packet_type", 1, 2, QUIC_LONG_PACKET_TYPES)
    fields_desc[3] = BitField("reserved_bits", None, 2)
    fields_desc.insert(
        4,
        BitFieldLenField(
            "packet_number_length", 1,
            2, length_of="packet_number",
        ),
    )
    fields_desc.extend([
        QuicVarLenField("length", None),
        XStrLenField(
            "packet_number", b"",
            length_from=PacketNumberInterface.get_packet_number_length,
        ),
    ])


class QuicInitial(Quic0Rtt):
    """
    Initial Packet {
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2) = 0,
      Reserved Bits (2),
      Packet Number Length (2),
      Version (32),
      Destination Connection ID Length (8),
      Destination Connection ID (0..160),
      Source Connection ID Length (8),
      Source Connection ID (0..160),
      Token Length (i),
      Token (..),
      Length (i),
      Packet Number (8..32),
      Packet Payload (..),
    }
    """
    name = "QUIC Initial"
    fields_desc = Quic0Rtt.fields_desc.copy()
    fields_desc[2] = BitEnumField("long_packet_type", 0, 2, QUIC_LONG_PACKET_TYPES)
    fields_desc.insert(10, QuicVarLenField("token_length", None, length_of="token"))
    fields_desc.insert(
        11,
        XStrLenField(
            "token", b"",
            length_from=lambda pkt: pkt.token_length,
        ),
    )


class QuicHandshake(Quic0Rtt):
    """
    Handshake Packet {
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2) = 2,
      Reserved Bits (2),
      Packet Number Length (2),
      Version (32),
      Destination Connection ID Length (8),
      Destination Connection ID (0..160),
      Source Connection ID Length (8),
      Source Connection ID (0..160),
      Length (i),
      Packet Number (8..32),
      Packet Payload (..),
    }
    """
    name = "QUIC Handshake"
    fields_desc = Quic0Rtt.fields_desc.copy()
    fields_desc[2] = BitEnumField("long_packet_type", 2, 2, QUIC_LONG_PACKET_TYPES)


class QuicRetry(QuicLongHeader):
    """
    Retry Packet {
      Header Form (1) = 1,
      Fixed Bit (1) = 1,
      Long Packet Type (2) = 3,
      Unused (4),
      Version (32),
      Destination Connection ID Length (8),
      Destination Connection ID (0..160),
      Source Connection ID Length (8),
      Source Connection ID (0..160),
      Retry Token (..),
      Retry Integrity Tag (128),
    }
    """
    name = "QUIC Retry"
    fields_desc = QuicLongHeader.fields_desc.copy()
    fields_desc[2] = BitEnumField("long_packet_type", 3, 2, QUIC_LONG_PACKET_TYPES)
    fields_desc[3] = BitField("unused", None, 4)
    fields_desc.extend([
        XStrField("retry_token", None, remain=16),
        XStrFixedLenField("retry_integrity_tag", None, 16),
    ])


class QuicVersionNegotiation(CommonBehavior):
    """
    Version Negotiation Packet {
      Header Form (1) = 1,
      Unused (7),
      Version (32) = 0,
      Destination Connection ID Length (8),
      Destination Connection ID (0..2040),
      Source Connection ID Length (8),
      Source Connection ID (0..2040),
      Supported Version (32) ...,
    }
    """
    name = "QUIC Version Negotiation"
    fields_desc = [
        BitEnumField("header_form", 1, 1, QUIC_HEADER_FORMS),
        BitField("unused", None, 7),
        IntEnumField("version", 0, {0: "0"}),
        BitFieldLenField(
            "destination_connection_id_length", None,
            8, length_of="destination_connection_id",
        ),
        XStrLenField(
            "destination_connection_id", b"", max_length=255,
            length_from=lambda pkt: pkt.destination_connection_id_length,
        ),
        BitFieldLenField(
            "source_connection_id_length", None,
            8, length_of="source_connection_id",
        ),
        XStrLenField(
            "source_connection_id", b"", max_length=255,
            length_from=lambda pkt: pkt.source_connection_id_length,
        ),
        FieldListField("supported_versions", None, XIntField("", None)),
    ]


class QuicShortHeader(PacketNumberInterface, FrameStorage):
    """
    Short Header Packet {
      Header Form (1) = 0,
      Fixed Bit (1) = 1,
      Spin Bit (1),
      Reserved Bits (2),
      Key Phase (1),
      Packet Number Length (2),
      Destination Connection ID (0..160),
      Packet Number (8..32),
      Packet Payload (..),
    }
    """
    name = "QUIC Short Header"
    fields_desc = [
        BitEnumField("header_form", 0, 1, QUIC_HEADER_FORMS),
        BitEnumField("fixed_bit", 1, 1, {1: "1"}),
        BitField("spin_bit", None, 1),
        BitField("reserved_bits", None, 2),
        BitField("key_phase", None, 1),
        BitFieldLenField("packet_number_length", 1, 2, length_of="packet_number"),
        XStrLenField(
            "destination_connection_id", b"", max_length=20,
            length_from=lambda pkt: pkt.get_destination_connection_id_length(),
        ),
        XStrLenField(
            "packet_number", b"",
            length_from=PacketNumberInterface.get_packet_number_length,
        ),
    ]

    # TODO: change when we know what to do here.
    def get_destination_connection_id_length(self) -> int:
        return min(
            20,
            len(self.original) - len(self.payload)
            - self.get_packet_number_length() - 1,
        )
