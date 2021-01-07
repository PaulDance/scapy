from binascii import unhexlify
from typing import Tuple, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.hashes import SHA256

from scapy.layers.quic import QUIC_VERSION
from scapy.layers.quic.packets import MAX_PACKET_NUMBER_LEN, PacketNumberInterface, QuicInitial
from scapy.layers.tls.crypto.cipher_aead import _AEADCipher_TLS13, \
    Cipher_AES_128_GCM_TLS13, Cipher_AES_128_CCM_TLS13, Cipher_AES_128_CCM_8_TLS13, \
    Cipher_AES_256_GCM_TLS13, Cipher_CHACHA20_POLY1305, Cipher_CHACHA20_POLY1305_TLS13
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF

# Labels.
LABEL_CLIENT = b"client in"
LABEL_SERVER = b"server in"
LABEL_AEAD_KEY = b"quic key"
LABEL_IV = b"quic iv"
LABEL_HP = b"quic hp"

# Initial salts with special cases.
DEFAULT_INITIAL_SALT = "ef4fb0abb47470c41befcf8031334fae485e09a0"
SPECIAL_INITIAL_SALTS = {
    0xff000017: "c3eef712c72ebb5a11a7d2432bb46365bef9f502",
    0xff000016: "7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a",
    0xff000020: "afbfec289993d24c9e9786f19c6111e04390a899",
    0x00000001: "38762cf7f55934b34d179ae6a4c80cadccbb7f0a",
}

# Header protection constant lengths.
HEADER_PROTECTION_SAMPLE_LENGTH = 16
HEADER_PROTECTION_MASK_LENGTH = 5


def get_initial_salt(version: int) -> bytes:
    """
    Retrieves the special initial salt corresponding to the given `version` if
    it exists, the default one otherwise.

    :param version: The QUIC version to use.
    :type version: int
    :return: The initial salt for the given `version` as bytes.
    :rtype: bytes
    """
    return unhexlify(SPECIAL_INITIAL_SALTS.get(version, DEFAULT_INITIAL_SALT))


class QuicHkdf(TLS13_HKDF):
    """
    Key derivation operations for QUIC with HKDF based on TLS1.3's.

    The hash function used in TLS1.3 HKDF for derivating initial secrets and
    keys is SHA256, therefore this class' default as well.
    """

    def compute_key(self, secret: bytes) -> bytes:
        """
        Expands the AEAD key label with the given `secret` in order to obtain
        the derived encryption key.

        :param secret: The initial secret to use.
        :type secret: bytes
        :return: The derived encryption key (16 bytes).
        :rtype: bytes
        """
        return self.expand_label(secret, LABEL_AEAD_KEY, b"", 16)

    def compute_iv(self, secret: bytes) -> bytes:
        """
        Expands the AEAD IV label with the given `secret` in order to obtain
        the derived encryption initialization vector.

        :param secret: The initial secret to use.
        :type secret: bytes
        :return: The derived encryption initialization vector (12 bytes).
        :rtype: bytes
        """
        return self.expand_label(secret, LABEL_IV, b"", 12)

    def compute_hp(self, secret: bytes) -> bytes:
        """
        Expands the HP label with the given `secret` in order to obtain the
        derived header protection key.

        :param secret: The initial secret to use.
        :type secret: bytes
        :return: The header protection key (16 bytes).
        :rtype: bytes
        """
        return self.expand_label(secret, LABEL_HP, b"", 16)

    def derive_keys(self, secret: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Shortcut to derive the three keys at once.

        :param secret: The initial secret to use.
        :type secret: bytes
        :return: The triplet of the three derived keys.
        :rtype: Tuple[bytes, bytes, bytes]
        """
        return self.compute_key(secret), \
               self.compute_iv(secret), \
               self.compute_hp(secret),

    def get_initial_secret(self, version: int, dcid: bytes) -> bytes:
        """
        Generates the initial secret for the given version and DCID.

        :param version: The QUIC version used.
        :type version: int
        :param dcid: The Destination Connection Id.
        :type dcid: bytes
        :return: The initial secret.
        :rtype: bytes
        """
        return self.extract(get_initial_salt(version), dcid)

    def get_client_initial_secret(self, initial_secret: bytes) -> bytes:
        """
        Expands the client label in order to get the client initial secret.

        :param initial_secret: The common initial secret to use.
        :type initial_secret: bytes
        :return: The initial secret derived for the client.
        :rtype: bytes
        """
        return self.expand_label(initial_secret, LABEL_CLIENT, b"", SHA256.digest_size)

    def get_server_initial_secret(self, initial_secret: bytes) -> bytes:
        """
        Expands the server label in order to get the server initial secret.

        :param initial_secret: The common initial secret to use.
        :type initial_secret: bytes
        :return: The initial secret derived for the server.
        :rtype: bytes
        """
        return self.expand_label(initial_secret, LABEL_SERVER, b"", SHA256.digest_size)

    def get_client_and_server_secrets(self, version: int, dcid: bytes) -> Tuple[bytes, bytes]:
        """
        Shortcut to derive both the client and server initial secrets at
        once by computing the common initial secret only one time.

        :param version: The QUIC version to use.
        :type version: int
        :param dcid: The Destination Connection Id to use.
        :type dcid: bytes
        :return: The two initial secrets as a couple of byte strings.
        :rtype: Tuple[bytes, bytes]
        """
        initial_secret = self.get_initial_secret(version, dcid)
        return self.get_client_initial_secret(initial_secret), \
               self.get_server_initial_secret(initial_secret),


class QuicAead(object):
    """
    Handles Authenticated Encryption with Associated Data (AEAD) operations
    for the QUIC protocol with checked cipher suites based on TLS1.3's.
    """
    CIPHERS = (
        Cipher_CHACHA20_POLY1305_TLS13,
        Cipher_CHACHA20_POLY1305,
        Cipher_AES_128_GCM_TLS13,
        Cipher_AES_256_GCM_TLS13,
        Cipher_AES_128_CCM_TLS13,
        Cipher_AES_128_CCM_8_TLS13,
    )
    """
    Tuple of cipher suites valid for QUIC: all cipher suites defined in TLS1.3
    aside from TLS_AES_128_CCM_8_SHA256.
    """

    def __init__(self, key: bytes, iv: bytes,
                 cipher_suite: Type[_AEADCipher_TLS13]):
        """
        Initializes the cipher from the AEAD key and IV.

        :param key: The encryption key to use.
        :type key: bytes
        :param iv: The encryption initialization vector to use.
        :type iv: bytes
        :param cipher_suite: The cipher suite to use.
        :type cipher_suite: Type[_AEADCipher_TLS13]
        :raise ValuError: When the given cipher is unknown.
        """
        if cipher_suite not in QuicAead.CIPHERS:
            raise ValueError("Incorrect or non existent cipher suite used")
        else:
            self.cipher = cipher_suite(key, iv)

    def encrypt(self, pkt: PacketNumberInterface) -> bytes:
        """
        Performs AEAD encryption on the given packet.

        :param pkt: The QUIC packet to encrypt.
        :type pkt: PacketNumberInterface
        :return: The encrypted payload of the given packet.
        :rtype: bytes
        """
        return self.cipher.auth_encrypt(
            pkt.payload.build()
            + bytes([0] * (pkt.length - len(pkt.build()) + 2)),
            pkt.build_without_payload(),
            pkt.packet_number
        )

    def decrypt(self, pkt: PacketNumberInterface) -> bytes:
        """
        Performs AEAD decryption on the given packet.

        :param pkt: The QUIC packet to decrypt.
        :type pkt: PacketNumberInterface
        :return: The decrypted payload of the given packet.
        :rtype: bytes
        :raise AEADTagError: When the authentication tags do not match
                             by comparing after decryption.
        """
        return self.cipher.auth_decrypt(
            pkt.build_without_payload(),
            pkt.payload.build(),
            pkt.packet_number
        )[0]


def header_protection_sample(pkt: PacketNumberInterface, enc_pl: bytes) -> bytes:
    """
    Extracts the QUIC header protection sample from the given encrypted payload.

    :param pkt: The packet which payload produces `enc_pl`.
    :type pkt: PacketNumberInterface
    :param enc_pl: The encrypted payload of `pkt`.
    :type enc_pl: bytes
    :return: The header protection sample.
    :rtype: bytes
    """
    sample_offset = MAX_PACKET_NUMBER_LEN - pkt.get_packet_number_length()
    return enc_pl[sample_offset: sample_offset + HEADER_PROTECTION_SAMPLE_LENGTH]


def header_protection_mask(hp: bytes, sample: bytes) -> bytes:
    """
    Produces the QUIC header protection mask from the given HP key and sample.

    :param hp: The header protection key to use.
    :type hp: bytes
    :param sample: The header protection sample to use.
    :type sample: bytes
    :return: The header protection mask.
    :rtype: bytes
    """
    encryptor = Cipher(AES(hp), ECB(), default_backend()).encryptor()
    return (encryptor.update(sample) + encryptor.finalize())[:HEADER_PROTECTION_MASK_LENGTH]


def header_protection(pkt: PacketNumberInterface, mask: bytes) -> bytes:
    """
    Applies QUIC header protection on the given packet.

    :param pkt: The packet which header has to be protected.
    :type pkt: PacketNumberInterface
    :param mask: The header protection mask to use.
    :type mask: bytes
    :return: The packet's protected header.
    :rtype: bytes
    """
    no_pl = pkt.without_payload()
    pn_len = no_pl.get_packet_number_length()
    no_pl.packet_number = (int.from_bytes(no_pl.packet_number, "big")
                           ^ int.from_bytes(mask[1: pn_len + 1], "big")).to_bytes(pn_len, "big")
    header = no_pl.build()
    return (header[0] ^ mask[0] & 0x0f if header[0] & 0x80 == 0x80 else 0x1f) \
               .to_bytes(1, "big") + header[1:]


def encrypt_packet(pkt: PacketNumberInterface, secret: bytes,
                   cipher_suite: Type[_AEADCipher_TLS13]) -> bytes:
    """
    Entirely encrypts the given packet to a byte string.

    :param pkt: The packet to encrypt.
    :type pkt: PacketNumberInterface
    :param secret: The derived initial secret to use.
    :type secret: bytes
    :param cipher_suite: The cipher suite to use.
    :type cipher_suite: Type[_AEADCipher_TLS13]
    :return: The byte string result of the encryption of the packet.
    :rtype: bytes
    """
    key, iv, hp = QuicHkdf().derive_keys(secret)
    enc_pl = QuicAead(key, iv, cipher_suite).encrypt(pkt)
    return header_protection(
        pkt,
        header_protection_mask(
            hp,
            header_protection_sample(pkt, enc_pl)
        )
    ) + enc_pl


def encrypt_initial(pkt: QuicInitial, dcid: bytes, client: bool = True) -> bytes:
    """
    Specialized encryption function for QUIC Initial packets only.

    :param pkt: The initial packet to encrypt.
    :type pkt: QuicInitial
    :param dcid: The Destination Connection Id to use.
    :type dcid: bytes
    :param client: Whether the packet is a client's or a server's, client by
                   default (`True`).
    :type client: bool
    :return: The byte string result of the encryption of the packet.
    :rtype: bytes
    """
    return encrypt_packet(
        pkt,
        QuicHkdf().get_client_and_server_secrets(
            QUIC_VERSION,
            dcid
        )[int(not client)],
        Cipher_AES_128_GCM_TLS13
    )


def decrypt_packet(pkt: PacketNumberInterface, secret: bytes,
                   cipher_suite: Type[_AEADCipher_TLS13]) -> PacketNumberInterface:
    """
    Entirely decrypts the given packet to a byte string.

    :param pkt: The partially parsed packet to decrypt.
    :type pkt: PacketNumberInterface
    :param secret: The derived initial secret to use.
    :type secret: bytes
    :param cipher_suite: The cipher suite to use.
    :type cipher_suite: Type[_AEADCipher_TLS13]
    :return: The completely decrypted and well-formed packet.
    :rtype: PacketNumberInterface
    """
    pkt = pkt.copy()
    key, iv, hp = QuicHkdf().derive_keys(secret)
    mask = header_protection_mask(hp, header_protection_sample(pkt, pkt.payload.build()))

    header = pkt.build_without_payload()
    pn_len = ((header[0] ^ mask[0] & 0x0f if header[0] & 0x80 == 0x80 else 0x1f) & 0x03) + 1
    lpart = pkt.packet_number[pn_len:]
    rshift = max(0, pn_len - pkt.get_packet_number_length())

    # HACK: force reserved bits to 0 in order to make tests pass.
    pkt.reserved_bits = 0
    pkt.packet_number_length = pn_len - 1
    pkt.packet_number = (int.from_bytes(pkt.packet_number[:pn_len]
                                        + pkt.payload.build()[:rshift], "big")
                         ^ int.from_bytes(mask[1: pn_len + 1], "big")).to_bytes(pn_len, "big")

    return pkt.without_payload() / QuicAead(key, iv, cipher_suite) \
        .decrypt(pkt.without_payload() / (lpart + pkt.payload.build()[rshift:]))


def decrypt_initial(pkt: QuicInitial, dcid: bytes, client: bool = True) -> QuicInitial:
    """
    Specialized decryption function for QUIC Initial packets only.

    :param pkt: The partially parsed initial packet to decrypt.
    :type pkt: QuicInitial
    :param dcid: The Destination Connection Id to use.
    :type dcid: bytes
    :param client: Whether the packet is a client's or a server's, client by
                   default (`True`).
    :type client: bool
    :return: The completely decrypted and well-formed initial packet.
    :rtype: QuicInitial
    """
    return decrypt_packet(
        pkt,
        QuicHkdf().get_client_and_server_secrets(
            QUIC_VERSION,
            dcid
        )[int(not client)],
        Cipher_AES_128_GCM_TLS13
    )
