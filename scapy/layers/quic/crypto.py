from binascii import unhexlify
from typing import Tuple
import struct

from cryptography.hazmat.primitives.hashes import SHA256

from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.crypto.cipher_aead import \
    Cipher_CHACHA20_POLY1305_TLS13, Cipher_CHACHA20_POLY1305, Cipher_AES_128_GCM_TLS13, \
    Cipher_AES_256_GCM_TLS13, Cipher_AES_128_CCM_TLS13, Cipher_AES_128_CCM_8_TLS13
from scapy.packet import Packet

# Labels
LABEL_CLIENT = b"client in"
LABEL_SERVER = b"server in"
LABEL_AEAD_KEY = b"quic key"
LABEL_IV = b"quic iv"
LABEL_HP = b"quic hp"

DEFAULT_INITIAL_SALT = "ef4fb0abb47470c41befcf8031334fae485e09a0"
SPECIAL_INITIAL_SALTS = {
    0xff000017: "c3eef712c72ebb5a11a7d2432bb46365bef9f502",
    0xff000016: "7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a",
    0xff000020: "afbfec289993d24c9e9786f19c6111e04390a899",
}


def get_initial_salt(version: int) -> bytes:
    return unhexlify(SPECIAL_INITIAL_SALTS.get(version, DEFAULT_INITIAL_SALT))


class QuicHkdf(TLS13_HKDF):
    @staticmethod
    def label(label: bytes, hash_value: bytes, length: int) -> bytes:
        full_label = b"tls13 " + label
        return struct.pack("!HB", length, len(full_label)) \
               + full_label \
               + struct.pack("!B", len(hash_value)) \
               + hash_value

    def compute_key(self, secret: bytes) -> bytes:
        return self.expand_label(secret, LABEL_AEAD_KEY, b"", 16)

    def compute_iv(self, secret: bytes) -> bytes:
        return self.expand_label(secret, LABEL_IV, b"", 12)

    def compute_hp(self, secret: bytes) -> bytes:
        return self.expand_label(secret, LABEL_HP, b"", 16)

    def derive_keys(self, secret: bytes) -> Tuple[bytes, bytes, bytes]:
        return self.compute_key(secret), \
               self.compute_iv(secret), \
               self.compute_hp(secret),

    def get_initial_secret(self, version: int, dcid: int) -> bytes:
        """
        Generate the initial secret.

        Hash function used in TLS1.3 HKDF for derivating initial secrets & keys
        is SHA256.

        :param version: The QUIC version used.
        :param dcid: The Destination Connection Id.
        :return: The initial secret.
        """
        return self.extract(get_initial_salt(version), dcid)

    def get_client_initial_secret(self, initial_secret: bytes) -> bytes:
        return self.expand_label(initial_secret, LABEL_CLIENT, b"", SHA256.digest_size)

    def get_server_initial_secret(self, initial_secret: bytes) -> bytes:
        return self.expand_label(initial_secret, LABEL_SERVER, b"", SHA256.digest_size)

    def get_client_and_server_secrets(self, version: int, dcid: int) -> Tuple[bytes, bytes]:
        initial_secret = self.get_initial_secret(version, dcid)
        return self.get_client_initial_secret(initial_secret), \
               self.get_server_initial_secret(initial_secret),


# Valid cipher suites: all cipher suites defined in TLS1.3 aside from TLS_AES_128_CCM_8_SHA256.
QUIC_CIPHERS = [
    Cipher_CHACHA20_POLY1305_TLS13,
    Cipher_CHACHA20_POLY1305,
    Cipher_AES_128_GCM_TLS13,
    Cipher_AES_256_GCM_TLS13,
    Cipher_AES_128_CCM_TLS13,
    Cipher_AES_128_CCM_8_TLS13,
]


def aead(key: bytes, iv: bytes, pkt: Packet, cipher_suite) -> bytes:
    if cipher_suite not in QUIC_CIPHERS:
        raise ValueError("Incorrect or non existent cipher suite used")
    else:
        return cipher_suite(key, iv).auth_encrypt(pkt.payload,
                                                  pkt.build_without_payload(),
                                                  pkt.packet_number)


def get_sample(pkt: Packet):
    pass


"""
sample_offset = 1 + len(connection_id) + 4
sample = packet[sample_offset..sample_offset+sample_length]

sample_offset = 7 + len(destination_connection_id) +
                    len(source_connection_id) +
                    len(payload_length) + 4
if packet_type == Initial:
    sample_offset += len(token_length) +
                     len(token)

sample = packet[sample_offset..sample_offset+sample_length]
"""


def hp_sample(hp_protection_key, sample, cipher_suite):
    pass


# Protect Initial packet
def encrypt_initial(pkt: Packet):
    pass
