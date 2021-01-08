from typing import Type, List

from scapy.fields import XStrLenField
from scapy.layers.quic.packets.common import CommonBehavior
from scapy.layers.quic.packets.fields import QuicVarLenField
from scapy.packet import Packet, NoPayload


class QuicFrame(CommonBehavior):
    """
    Frame {
      Frame Type (i),
      Type-Dependent Fields (..),
    }
    """
    fields_desc = [
        QuicVarLenField("frame_type", None),
    ]

    def guess_payload_class(self, payload: bytes) -> Type[Packet]:
        return QUIC_FRAME_TYPES[self.frame_type]


class FrameStorage(CommonBehavior):
    """
    Represents a packet capable of storing a linked-list of frames.
    """

    def guess_payload_class(self, payload: bytes) -> Type[Packet]:
        return QuicFrame

    def get_frames(self) -> List[QuicFrame]:
        frames = []
        self.payload.payload.get_frames_fill(frames)
        return frames

    def get_frames_fill(self, frames: List[QuicFrame]) -> None:
        if not isinstance(self, NoPayload):
            frames.append(self.without_payload())

            if not isinstance(self.payload.payload, NoPayload):
                self.payload.payload.get_frames_fill(frames)


class PaddingFrame(FrameStorage):
    """
    PADDING Frame {
      Type (i) = 0x00,
    }
    """


class PingFrame(FrameStorage):
    """
    PING Frame {
      Type (i) = 0x01,
    }
    """


class AckFrame(FrameStorage):
    """
    ACK Frame {
      Type (i) = 0x02..0x03,
      Largest Acknowledged (i),
      ACK Delay (i),
      ACK Range Count (i),
      First ACK Range (i),
      ACK Range (..) ...,
      [ECN Counts (..)],
    }
    """
    fields_desc = [
        QuicVarLenField("largest_acknowledged", None),
        QuicVarLenField("ack_delay", None),
        QuicVarLenField("ack_range_count", None),
        QuicVarLenField("first_ack_range", None),
        # ACK Range (..) ...,
        # [ECN Counts (..)],
    ]


class ResetStreamFrame(FrameStorage):
    """
    RESET_STREAM Frame {
      Type (i) = 0x04,
      Stream ID (i),
      Application Protocol Error Code (i),
      Final Size (i),
    }
    """


class StopSendingFrame(FrameStorage):
    """
    STOP_SENDING Frame {
      Type (i) = 0x05,
      Stream ID (i),
      Application Protocol Error Code (i),
    }
    """


class CryptoFrame(FrameStorage):
    """
    CRYPTO Frame {
      Type (i) = 0x06,
      Offset (i),
      Length (i),
      Crypto Data (..),
    }
    """
    fields_desc = [
        QuicVarLenField("offset", None),
        QuicVarLenField("length", None, length_of="crypto_data"),
        XStrLenField("crypto_data", b"", length_from=lambda pkt: pkt.length),
    ]


class NewTokenFrame(FrameStorage):
    """
    NEW_TOKEN Frame {
      Type (i) = 0x07,
      Token Length (i),
      Token (..),
    }
    """


class StreamFrame(FrameStorage):
    """
    STREAM Frame {
      Type (i) = 0x08..0x0f,
      Stream ID (i),
      [Offset (i)],
      [Length (i)],
      Stream Data (..),
    }
    """


class MaxDataFrame(FrameStorage):
    """
    MAX_DATA Frame {
      Type (i) = 0x10,
      Maximum Data (i),
    }
    """


class MaxStreamDataFrame(FrameStorage):
    """
    MAX_STREAM_DATA Frame {
      Type (i) = 0x11,
      Stream ID (i),
      Maximum Stream Data (i),
    }
    """


class MaxStreamsFrame(FrameStorage):
    """
    MAX_STREAMS Frame {
      Type (i) = 0x12..0x13,
      Maximum Streams (i),
    }
    """


class DataBlockedFrame(FrameStorage):
    """
    DATA_BLOCKED Frame {
      Type (i) = 0x14,
      Maximum Data (i),
    }
    """


class StreamDataBlockedFrame(FrameStorage):
    """
    STREAM_DATA_BLOCKED Frame {
      Type (i) = 0x15,
      Stream ID (i),
      Maximum Stream Data (i),
    }
    """


class StreamsBlockedFrame(FrameStorage):
    """
    STREAMS_BLOCKED Frame {
      Type (i) = 0x16..0x17,
      Maximum Streams (i),
    }
    """


class NewConnectionIdFrame(FrameStorage):
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


class RetireConnectionIdFrame(FrameStorage):
    """
    RETIRE_CONNECTION_ID Frame {
      Type (i) = 0x19,
      Sequence Number (i),
    }
    """


class PathChallengeFrame(FrameStorage):
    """
    PATH_CHALLENGE Frame {
      Type (i) = 0x1a,
      Data (64),
    }
    """


class PathResponseFrame(FrameStorage):
    """
    PATH_RESPONSE Frame {
      Type (i) = 0x1b,
      Data (64),
    }
    """


class ConnectionCloseFrame(FrameStorage):
    """
    CONNECTION_CLOSE Frame {
      Type (i) = 0x1c..0x1d,
      Error Code (i),
      [Frame Type (i)],
      Reason Phrase Length (i),
      Reason Phrase (..),
    }
    """


class HandshakeDoneFrame(FrameStorage):
    """
    HANDSHAKE_DONE Frame {
      Type (i) = 0x1e,
    }
    """


QUIC_FRAME_TYPES = {
    0x00: PaddingFrame,
    0x01: PingFrame,
    **{i: AckFrame for i in range(0x02, 0x03 + 1)},
    0x04: ResetStreamFrame,
    0x05: StopSendingFrame,
    0x06: CryptoFrame,
    0x07: NewTokenFrame,
    **{i: StreamFrame for i in range(0x8, 0x0f + 1)},
    0x10: MaxDataFrame,
    0x11: MaxStreamDataFrame,
    **{i: MaxStreamsFrame for i in range(0x12, 0x13 + 1)},
    0x14: DataBlockedFrame,
    0x15: StreamDataBlockedFrame,
    **{i: StreamsBlockedFrame for i in range(0x16, 0x17 + 1)},
    0x18: NewConnectionIdFrame,
    0x19: RetireConnectionIdFrame,
    0x1a: PathChallengeFrame,
    0x1b: PathResponseFrame,
    **{i: ConnectionCloseFrame for i in range(0x1c, 0x1d + 1)},
    0x1e: HandshakeDoneFrame,
}
