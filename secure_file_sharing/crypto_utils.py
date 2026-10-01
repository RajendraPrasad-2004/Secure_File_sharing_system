"""
crypto_utils.py - All cryptographic operations (hybrid encryption).

Only vetted primitives from the `cryptography` library are used. No custom
algorithms are implemented.

WHY HYBRID ENCRYPTION?
----------------------
* AES-256-GCM (symmetric) is FAST and handles files of any size. It also
  provides built-in integrity (authentication tag), so tampering is detected.
  Its weakness: both sides need the same secret key - how do you share it?
* RSA-2048-OAEP (asymmetric) solves key distribution: anyone can encrypt with
  the public key, only the private-key holder can decrypt. But RSA is slow
  and can only encrypt tiny messages (< ~190 bytes with OAEP-SHA256), so it
  is unsuitable for whole files.

Hybrid design: AES encrypts the FILE, RSA encrypts the (32-byte) AES KEY.
Each file gets a fresh random AES key, so compromise of one key exposes
only one file.
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

AES_KEY_BYTES = 32      # 256-bit key
NONCE_BYTES = 12        # 96-bit nonce recommended for GCM
SALT_BYTES = 16
RSA_KEY_BITS = 2048
# scrypt cost parameters (memory-hard KDF used to derive the key-wrapping key)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


class DecryptionError(Exception):
    """Raised when authenticated decryption fails (wrong key or tampering)."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# --------------------------------------------------------------------------
# RSA key pair
# --------------------------------------------------------------------------
def generate_rsa_keypair():
    """Return (public_pem, private_pem) as bytes. RSA-2048."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),   # we wrap it ourselves below
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_pem, private_pem


# --------------------------------------------------------------------------
# Private-key protection (password-derived key)
# --------------------------------------------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=AES_KEY_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def protect_private_key(private_pem: bytes, password: str) -> str:
    """
    Encrypt the RSA private key with AES-256-GCM using a key derived from the
    user's password via scrypt. Stored format: base64(salt || nonce || ciphertext).
    """
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, private_pem, b"private-key")
    return b64e(salt + nonce + ct)


def unlock_private_key(blob: str, password: str) -> bytes:
    """Reverse of protect_private_key. Raises DecryptionError on wrong password."""
    raw = b64d(blob)
    salt, nonce, ct = raw[:SALT_BYTES], raw[SALT_BYTES:SALT_BYTES + NONCE_BYTES], raw[SALT_BYTES + NONCE_BYTES:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, b"private-key")
    except InvalidTag as exc:
        raise DecryptionError("Could not unlock private key") from exc


# --------------------------------------------------------------------------
# AES-256-GCM file encryption
# --------------------------------------------------------------------------
def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(plaintext: bytes, key: bytes, aad: bytes):
    """
    Encrypt with AES-256-GCM. Returns (nonce, ciphertext_with_tag).
    The 16-byte authentication tag is appended to the ciphertext.
    `aad` (associated data) is authenticated but not encrypted; we bind the
    ciphertext to its storage filename so files cannot be swapped.
    """
    nonce = os.urandom(NONCE_BYTES)     # unique per encryption
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Decrypt and VERIFY integrity. Raises DecryptionError if modified."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("Integrity check failed: file was modified or key is wrong") from exc


# --------------------------------------------------------------------------
# RSA-OAEP key wrapping
# --------------------------------------------------------------------------
def _oaep():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def rsa_encrypt_key(public_pem: bytes, aes_key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key.encrypt(aes_key, _oaep())


def rsa_decrypt_key(private_pem: bytes, encrypted_key: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    try:
        return private_key.decrypt(encrypted_key, _oaep())
    except ValueError as exc:
        raise DecryptionError("Could not decrypt AES key with this private key") from exc
