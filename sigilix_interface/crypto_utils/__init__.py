import base64
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)
import hashlib


elliptic_curve = ec.SECP256R1()
key_size_in_bytes = (elliptic_curve.key_size + 7) // 8


def serialize_signature(r: int, s: int) -> bytes:
    # Ensure that r and s are padded to key_size_in_bytes
    r_bytes = r.to_bytes(key_size_in_bytes, "big")
    s_bytes = s.to_bytes(key_size_in_bytes, "big")
    return r_bytes + s_bytes


def deserialize_signature(signature: bytes) -> Tuple[int, int]:
    if len(signature) != 2 * key_size_in_bytes:
        raise ValueError("signature is not the correct size")

    r = int.from_bytes(signature[:key_size_in_bytes], "big")
    s = int.from_bytes(signature[key_size_in_bytes:], "big")
    return r, s


def generate_ecdsa_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(elliptic_curve, default_backend())


def base64_to_bytes(data: str) -> bytes:
    return base64.b64decode(data)


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def ecdsa_public_key_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(elliptic_curve, data)


def ecdsa_public_key_to_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def hash_data(data: bytes) -> bytes:
    # digest = hashes.Hash(hashes.SHA256(), default_backend())
    # digest.update(data)
    # return digest.finalize()
    return hashlib.sha256(data).digest()


def validate_signature(
    public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes
) -> bool:
    r, s = deserialize_signature(signature)

    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def sign_message(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    return serialize_signature(r, s)


def ecdsa_private_key_to_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.private_numbers().private_value.to_bytes(byteorder="big", length=key_size_in_bytes) + ecdsa_public_key_to_bytes(private_key.public_key())


def ecdsa_private_key_from_bytes(data: bytes) -> ec.EllipticCurvePrivateKey:
    if len(data) != (3 * key_size_in_bytes) + 1:
        raise ValueError(f"invalid key size: {len(data)} instead of {key_size_in_bytes}")
    d = int.from_bytes(data[:key_size_in_bytes], "big")
    data = data[key_size_in_bytes:]
    data = data[1:]  # remove curve type
    x = int.from_bytes(data[:key_size_in_bytes], "big")
    data = data[key_size_in_bytes:]
    y = int.from_bytes(data[:key_size_in_bytes], "big")
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, elliptic_curve)
    private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
    return private_numbers.private_key(default_backend())


def generate_user_id_by_public_key(public_key):
    data = ecdsa_public_key_to_bytes(public_key)
    hashed = hash_data(data)
    return int.from_bytes(hashed[:8], byteorder="big")


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


def rsa_private_key_to_bytes_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def rsa_private_key_from_bytes_pem(data: bytes) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(
        data,
        password=None,
        backend=default_backend(),
    )


def rsa_public_key_to_bytes_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def rsa_public_key_from_bytes_pem(data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(
        data,
        backend=default_backend(),
    )


def rsa_encrypt(public_key: rsa.RSAPublicKey, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


if __name__ == "__main__":

    def main():
        print(bytes_to_base64(ecdsa_private_key_to_bytes(generate_ecdsa_private_key())))

    main()


__all__ = [
    "base64_to_bytes",
    "bytes_to_base64",
    "ecdsa_public_key_from_bytes",
    "ecdsa_public_key_to_bytes",
    "hash_data",
    "validate_signature",
    "sign_message",
    "ecdsa_private_key_to_bytes",
    "ecdsa_private_key_from_bytes",
    "generate_user_id_by_public_key",
    "generate_rsa_key",
    "rsa_private_key_to_bytes_pem",
    "rsa_private_key_from_bytes_pem",
    "rsa_public_key_to_bytes_pem",
    "rsa_public_key_from_bytes_pem",
    "rsa_encrypt",
]
