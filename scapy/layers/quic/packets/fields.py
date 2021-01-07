from typing import Any, Optional, Tuple

from scapy.fields import Field


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
