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


QUIC_FRAME_TYPES = {
    0x00: PaddingFrame,
    0x01: PingFrame,
    0x02: AckFrame,
    0x03: AckFrame,
    0x06: CryptoFrame,
}
