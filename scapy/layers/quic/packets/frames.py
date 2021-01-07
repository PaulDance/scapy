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

if __name__ == "__main__":
    from scapy.layers.quic.packets import QuicInitial

    print(repr(QuicInitial(bytes.fromhex(
        "c3ff000020088394c8f03e5157080000449e00000002060040f1010000ed0303"
        "ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c"
        "00000413011302010000c000000010000e00000b6578616d706c652e636f6dff"
        "01000100000a00080006001d0017001800100007000504616c706e0005000501"
        "00000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171"
        "fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306"
        "030203080408050806002d00020101001c00024001ffa500320408ffffffffff"
        "ffffff05048000ffff07048000ffff0801100104800075300901100f088394c8"
        "f03e51570806048000ffff"
    )).get_frames()))
    print(repr(QuicInitial(bytes.fromhex(
        "c1ff0000200008f067a5502a4262b5004075000102000000000600405a020000"
        "560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a"
        "045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144e"
        "ca684d1081287c834d5311bcf32bb9da1a002b00020304"
    )).get_frames()))
