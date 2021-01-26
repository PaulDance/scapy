from typing import Type, List, Optional

from scapy.fields import XStrLenField, ConditionalField, XStrFixedLenField, \
    BitFieldLenField, Field
from scapy.layers.quic.packets.common import CommonBehavior
from scapy.layers.quic.packets.fields import QuicVarLenField
from scapy.packet import Packet, NoPayload


class FrameType(CommonBehavior):
    """
    Frame {
      Frame Type (i),
      Type-Dependent Fields (..),
    }
    """
    FRAME_TYPES = tuple()
    fields_desc = [
        QuicVarLenField("frame_type", None),
    ]

    @classmethod
    def default_type(cls) -> int:
        return cls.FRAME_TYPES[0]

    @classmethod
    def fields_with_type(cls, default_type: Optional[int]) -> List[Field]:
        return [QuicVarLenField("frame_type", default_type)] \
               + cls.fields_desc.copy()[1:]


class FrameStorage(CommonBehavior):
    """
    Represents a packet capable of storing a linked list of frames.
    """

    def guess_payload_class(self, payload: bytes) -> Type[Packet]:
        return QUIC_FRAME_TYPES.get(FrameType(payload).frame_type, None)

    def get_frames(self) -> List['FrameStorage']:
        """
        Simpler getter for frames instead of the linked list parsing result.

        :return: The array of frames contained in the packet's payload.
        :rtype: List[FrameStorage]
        """
        frames = []
        self.payload.get_frames_fill(frames)
        return frames

    def get_frames_fill(self, frames: List['FrameStorage']) -> None:
        """
        Recursive "back-end" for `get_frames`: appends frames to the given list.

        :param frames: The extensible array to fill up with parsed frames.
        :type frames: List[FrameStorage]
        :rtype: None
        """
        if not isinstance(self, NoPayload):
            frames.append(self.without_payload())

            if not isinstance(self.payload, NoPayload):
                self.payload.get_frames_fill(frames)


class PaddingFrame(FrameType, FrameStorage):
    """
    PADDING Frame {
      Type (i) = 0x00,
    }
    """
    FRAME_TYPES = (0x00,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0])


class PingFrame(FrameType, FrameStorage):
    """
    PING Frame {
      Type (i) = 0x01,
    }
    """
    FRAME_TYPES = (0x01,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0])


class AckFrame(FrameType, FrameStorage):
    """
    ACK Frame {
      Type (i) = 0x02..0x03,
      Largest Acknowledged (i),
      ACK Delay (i),
      ACK Range Count (i),
      First ACK Range (i),
      ACK Ranges (..) ...,
      [ECN Counts (..)],
    }
    """
    FRAME_TYPES = (0x02, 0x03)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("largest_acknowledged", None),
        QuicVarLenField("ack_delay", None),
        QuicVarLenField("ack_range_count", None),
        QuicVarLenField("first_ack_range", None),
        ConditionalField(
            XStrLenField(
                "ack_ranges", None,
                length_from=lambda pkt: pkt.first_ack_range,
            ),
            lambda pkt: pkt.first_ack_range != 0,
        ),
        ConditionalField(
            QuicVarLenField("ect0_count", None),
            lambda pkt: pkt.frame_type == 0x3,
        ),
        ConditionalField(
            QuicVarLenField("ect1_count", None),
            lambda pkt: pkt.frame_type == 0x3,
        ),
        ConditionalField(
            QuicVarLenField("ecn_ce_count", None),
            lambda pkt: pkt.frame_type == 0x3,
        ),
    ]


class ResetStreamFrame(FrameType, FrameStorage):
    """
    RESET_STREAM Frame {
      Type (i) = 0x04,
      Stream ID (i),
      Application Protocol Error Code (i),
      Final Size (i),
    }
    """
    FRAME_TYPES = (0x04,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("stream_id", None),
        QuicVarLenField("application_protocol_error_code", None),
        QuicVarLenField("final_size", None),
    ]


class StopSendingFrame(FrameType, FrameStorage):
    """
    STOP_SENDING Frame {
      Type (i) = 0x05,
      Stream ID (i),
      Application Protocol Error Code (i),
    }
    """
    FRAME_TYPES = (0x05,)
    fields_desc = ResetStreamFrame.fields_with_type(FRAME_TYPES[0])[:-1]


class CryptoFrame(FrameType, FrameStorage):
    """
    CRYPTO Frame {
      Type (i) = 0x06,
      Offset (i),
      Length (i),
      Crypto Data (..),
    }
    """
    FRAME_TYPES = (0x06,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("offset", None),
        QuicVarLenField("length", None, length_of="crypto_data"),
        XStrLenField("crypto_data", b"", length_from=lambda pkt: pkt.length),
    ]


class NewTokenFrame(FrameType, FrameStorage):
    """
    NEW_TOKEN Frame {
      Type (i) = 0x07,
      Token Length (i),
      Token (..),
    }
    """
    FRAME_TYPES = (0x07,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("token_length", None, length_of="token"),
        XStrLenField("token", b"", length_from=lambda pkt: pkt.token_length),
    ]


class StreamFrame(FrameType, FrameStorage):
    """
    STREAM Frame {
      Type (i) = 0x08..0x0f,
      Stream ID (i),
      [Offset (i)],
      [Length (i)],
      Stream Data (..),
    }
    """
    FRAME_TYPES = tuple(range(0x08, 0x0f + 1))
    OFF_BIT = 2
    LEN_BIT = 1
    FIN_BIT = 0
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("stream_id", None),
        ConditionalField(
            QuicVarLenField("offset", None),
            lambda pkt: pkt.has_off_bit(),
        ),
        ConditionalField(
            QuicVarLenField("length", None),
            lambda pkt: pkt.has_len_bit(),
        ),
        XStrLenField(
            "stream_data", b"",
            length_from=lambda pkt:
            pkt.length if pkt.length is not None
            else 2 ** 64,
        ),
    ]

    def get_type_bit(self, pos: int) -> int:
        return self.frame_type >> pos & 1

    def get_off_bit(self) -> int:
        return self.get_type_bit(StreamFrame.OFF_BIT)

    def get_len_bit(self) -> int:
        return self.get_type_bit(StreamFrame.LEN_BIT)

    def get_fin_bit(self) -> int:
        return self.get_type_bit(StreamFrame.FIN_BIT)

    def has_off_bit(self) -> bool:
        return self.get_off_bit() == 1

    def has_len_bit(self) -> bool:
        return self.get_len_bit() == 1

    def has_fin_bit(self) -> bool:
        return self.get_fin_bit() == 1


class MaxDataFrame(FrameType, FrameStorage):
    """
    MAX_DATA Frame {
      Type (i) = 0x10,
      Maximum Data (i),
    }
    """
    FRAME_TYPES = (0x10,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("maximum_data", None),
    ]


class MaxStreamDataFrame(FrameType, FrameStorage):
    """
    MAX_STREAM_DATA Frame {
      Type (i) = 0x11,
      Stream ID (i),
      Maximum Stream Data (i),
    }
    """
    FRAME_TYPES = (0x11,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("stream_id", None),
        QuicVarLenField("maximum_stream_data", None),
    ]


class MaxStreamsFrame(FrameType, FrameStorage):
    """
    MAX_STREAMS Frame {
      Type (i) = 0x12..0x13,
      Maximum Streams (i),
    }
    """
    FRAME_TYPES = (0x12, 0x13)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("maximum_streams", None),
    ]


class DataBlockedFrame(FrameType, FrameStorage):
    """
    DATA_BLOCKED Frame {
      Type (i) = 0x14,
      Maximum Data (i),
    }
    """
    FRAME_TYPES = (0x14,)
    fields_desc = MaxDataFrame.fields_with_type(FRAME_TYPES[0])


class StreamDataBlockedFrame(FrameType, FrameStorage):
    """
    STREAM_DATA_BLOCKED Frame {
      Type (i) = 0x15,
      Stream ID (i),
      Maximum Stream Data (i),
    }
    """
    FRAME_TYPES = (0x15,)
    fields_desc = MaxStreamDataFrame.fields_with_type(FRAME_TYPES[0])


class StreamsBlockedFrame(FrameType, FrameStorage):
    """
    STREAMS_BLOCKED Frame {
      Type (i) = 0x16..0x17,
      Maximum Streams (i),
    }
    """
    FRAME_TYPES = (0x16, 0x17)
    fields_desc = MaxStreamsFrame.fields_with_type(FRAME_TYPES[0])


class NewConnectionIdFrame(FrameType, FrameStorage):
    """
    NEW_CONNECTION_ID Frame {
      Type (i) = 0x18,
      Sequence Number (i),
      Retire Prior To (i),
      Length (8),
      Connection ID (8..160),
      Stateless Reset Token (128),
    }
    """
    FRAME_TYPES = (0x18,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("sequence_number", None),
        QuicVarLenField("retire_prior_to", None),
        BitFieldLenField(
            "connection_id_length", None,
            8, length_of="connection_id",
        ),
        XStrLenField(
            "connection_id",
            b"", max_length=20,
            length_from=lambda pkt: pkt.length,
        ),
        XStrFixedLenField("retry_integrity_tag", None, 16),
    ]


class RetireConnectionIdFrame(FrameType, FrameStorage):
    """
    RETIRE_CONNECTION_ID Frame {
      Type (i) = 0x19,
      Sequence Number (i),
    }
    """
    FRAME_TYPES = (0x19,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("sequence_number", None),
    ]


class PathChallengeFrame(FrameType, FrameStorage):
    """
    PATH_CHALLENGE Frame {
      Type (i) = 0x1a,
      Data (64),
    }
    """
    FRAME_TYPES = (0x1a,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        XStrFixedLenField("data", None, 8),
    ]


class PathResponseFrame(FrameType, FrameStorage):
    """
    PATH_RESPONSE Frame {
      Type (i) = 0x1b,
      Data (64),
    }
    """
    FRAME_TYPES = (0x1b,)
    fields_desc = PathChallengeFrame.fields_with_type(FRAME_TYPES[0])


class ConnectionCloseFrame(FrameType, FrameStorage):
    """
    CONNECTION_CLOSE Frame {
      Type (i) = 0x1c..0x1d,
      Error Code (i),
      [Error Frame Type (i)],
      Reason Phrase Length (i),
      Reason Phrase (..),
    }
    """
    FRAME_TYPES = (0x1c, 0x1d)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0]) + [
        QuicVarLenField("error_code", None),
        ConditionalField(
            QuicVarLenField("error_frame_type", None),
            lambda pkt: pkt.frame_type == 0x1c,
        ),
        QuicVarLenField("reason_phrase_length", None, length_of="reason_phrase"),
        XStrLenField(
            "reason_phrase", b"",
            length_from=lambda pkt: pkt.reason_phrase_length,
        ),
    ]


class HandshakeDoneFrame(FrameType, FrameStorage):
    """
    HANDSHAKE_DONE Frame {
      Type (i) = 0x1e,
    }
    """
    FRAME_TYPES = (0x1e,)
    fields_desc = FrameType.fields_with_type(FRAME_TYPES[0])


QUIC_FRAME_TYPES = {frame_type: cls for cls in (
    PaddingFrame,
    PingFrame,
    AckFrame,
    ResetStreamFrame,
    StopSendingFrame,
    CryptoFrame,
    NewTokenFrame,
    StreamFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    DataBlockedFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    NewConnectionIdFrame,
    RetireConnectionIdFrame,
    PathChallengeFrame,
    PathResponseFrame,
    ConnectionCloseFrame,
    HandshakeDoneFrame,
) for frame_type in cls.FRAME_TYPES}
