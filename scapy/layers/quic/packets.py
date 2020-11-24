from typing import Tuple, Any, Optional

from scapy.fields import BitField, BitEnumField, BitFieldLenField, Field, XStrLenField, \
    XIntField, XStrField, XStrFixedLenField, IntEnumField, FieldListField
from scapy.packet import Packet

QUIC_VERSION = 0xff000020
QUIC_HEADER_FORMS = {0: "Short", 1: "Long"}
QUIC_LONG_PACKET_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
MAX_PACKET_NUMBER_LEN = 4


def decode_length(b: bytes) -> Tuple[bytes, int]:
    """
    Decodes the given bytes of variable-length integer representation to a
    couple of the bytes of the integer and the integer itself.

    QUIC-TLS, Section 16. defines variable-length integers and Appendix A.1.
    shows a pseudocode for a variable-length integer decoding algorithm.

    :param b: The bytes of the varint representation to convert.
    :type b: bytes
    :return: The couple of the bytes of the integer and the integer itself.
    :rtype: Tuple[bytes, int]
    """
    ba = bytearray(b)
    ba[0] = b[0] & 0x3f
    o1 = b[0] & 0xc0

    if o1 == 0x00:
        return b[1:], int.from_bytes(ba[0:1], "big")
    elif o1 == 0x40:
        return b[2:], int.from_bytes(ba[0:2], "big")
    elif o1 == 0x80:
        return b[4:], int.from_bytes(ba[0:4], "big")
    elif o1 == 0xc0:
        return b[8:], int.from_bytes(ba[0:8], "big")


def encode_length(i: Optional[int]) -> bytes:
    """
    Encodes the given number to its variable-length integer representation.

    QUIC-TLS, Section 16. defines variable-length integers and Appendix A.1.
    shows a pseudocode for a variable-length integer decoding algorithm.

    :param i: The number to convert. `None` means the zero byte.
    :type i: Optional[int]
    :return: The number encoded as a variable-length integer.
    :rtype: bytes
    """
    if i is None:
        return b'\x00'
    else:
        for bound, length, mask in (
                (0x40, 1, 0x00),
                (0x4000, 2, 0x40),
                (0x40000000, 4, 0x80),
                (0x4000000000000000, 8, 0xc0)
        ):
            if i < bound:
                bytes_array = bytearray(i.to_bytes(length, "big"))
                bytes_array[0] ^= mask
                return bytes(bytes_array)

        raise ValueError("integer too big")


class QuicVarLenField(Field):
    """
    The QUIC variable-length integer encoding reserves the two most significant
    bits of the first byte to encode the base-2 logarithm of the integer
    encoding length in bytes. The integer value is encoded on the remaining
    bits, in network byte order. (QUIC-TLS, Section 16.)
    """
    __slots__ = ["length_of"]

    def __init__(self, name: str, default: Any, length_of: Optional[str] = None) -> None:
        Field.__init__(self, name, default)
        self.length_of = length_of

    def i2m(self, pkt, x) -> bytes:
        if x is None and self.length_of is not None:
            fld, fval = pkt.getfield_and_val(self.length_of)
            x = fld.i2len(pkt, fval)

        return encode_length(x)

    def m2i(self, pkt, x) -> Tuple[bytes, int]:
        return decode_length(x)

    def getfield(self, pkt, s) -> Tuple[bytes, int]:
        return self.m2i(pkt, s)

    def addfield(self, pkt, s, val) -> bytes:
        return s + self.i2m(pkt, val)


class CommonBehavior(Packet):
    """
    Interface-like class adding methods common to all packet types.
    """

    def without_payload(self) -> 'CommonBehavior':
        """
        Clones the packet, removes the payload and returns the result.

        :return: A copy of the packet without the payload.
        :rtype: CommonBehavior
        """
        pkt = self.copy()
        pkt.remove_payload()
        return pkt

    def build_without_payload(self) -> bytes:
        """
        Clones the packet, removes the payload, builds the byte string and
        returns the result.

        :return: The bytes of the header fields without the payload.
        :rtype: bytes
        """
        return self.without_payload().build()


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
        BitFieldLenField("destination_connection_id_length", None, 8,
                         length_of="destination_connection_id"),
        XStrLenField("destination_connection_id", b"", max_length=20,
                     length_from=lambda pkt: pkt.destination_connection_id_length),
        BitFieldLenField("source_connection_id_length", None, 8, length_of="source_connection_id"),
        XStrLenField("source_connection_id", b"", max_length=20,
                     length_from=lambda pkt: pkt.source_connection_id_length),
    ]


class Quic0Rtt(QuicLongHeader, PacketNumberInterface):
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
    fields_desc.insert(4, BitFieldLenField("packet_number_length", 1, 2, length_of="packet_number"))
    fields_desc.extend([
        QuicVarLenField("length", None),
        XStrLenField("packet_number", b"",
                     length_from=PacketNumberInterface.get_packet_number_length)
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
    fields_desc.insert(11, XStrLenField("token", b"", length_from=lambda pkt: pkt.token_length))


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
        BitFieldLenField("destination_connection_id_length", None, 8,
                         length_of="destination_connection_id"),
        XStrLenField("destination_connection_id", b"", max_length=255,
                     length_from=lambda pkt: pkt.destination_connection_id_length),
        BitFieldLenField("source_connection_id_length", None, 8, length_of="source_connection_id"),
        XStrLenField("source_connection_id", b"", max_length=255,
                     length_from=lambda pkt: pkt.source_connection_id_length),
        FieldListField("supported_versions", None, XIntField("", None)),
    ]


class QuicShortHeader(PacketNumberInterface):
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
        XStrLenField("destination_connection_id", b"", max_length=20,
                     length_from=lambda pkt: pkt.get_destination_connection_id_length()),
        XStrLenField("packet_number", b"",
                     length_from=PacketNumberInterface.get_packet_number_length)
    ]

    # TODO: change when we know what to do here.
    def get_destination_connection_id_length(self) -> int:
        return min(20,
                   len(self.original) - len(self.payload)
                   - self.get_packet_number_length() - 1)
