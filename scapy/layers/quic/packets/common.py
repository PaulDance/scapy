from scapy.packet import Packet


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
