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
    return private_key.private_numbers().private_value.to_bytes(
        byteorder="big", length=key_size_in_bytes
    ) + ecdsa_public_key_to_bytes(private_key.public_key())


def ecdsa_private_key_from_bytes(data: bytes) -> ec.EllipticCurvePrivateKey:
    if len(data) != (3 * key_size_in_bytes) + 1:
        raise ValueError(
            f"invalid key size: {len(data)} instead of {key_size_in_bytes}"
        )
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
    return int.from_bytes(hashed[:4], byteorder="big")


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


def rsa_public_key_to_bytes_der(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def rsa_public_key_from_bytes_der(data: bytes) -> rsa.RSAPublicKey:
    # return serialization.load_pem_public_key(
    #     data,
    #     backend=default_backend(),
    # )
    return serialization.load_der_public_key(
        data,
        backend=default_backend()
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
        a = "039FCFE20EDAA14049FEE0A79D307B6F63E7C19CEE5D148CE832F1B594C9FB3352"
        a_bytes = bytes.fromhex(a)
        #
        k = ecdsa_public_key_from_bytes(a_bytes)
        # print(k.public_numbers())
        # print(ecdsa_public_key_to_bytes(k).hex())
        # print(generate_user_id_by_public_key(k))
        data_str = bytes.fromhex("0a4104ba21baad1cb70701d86721b6e98a6dec661454ebdaa2c1eefb16494fe11f330c27ef14129c93fbd9dbeb76a52a85efb0aadf4d1b66750e2ff467ec05a0707462125e305c300d06092a864886f70d0101010500034b00304802410091e60d8b43f9a087873a413d16b7efb08a8e931fcce2f30d9a9c2f81c5edb948cb3182e33874d3dbf053dd4aa86c4276808c193bed09283a5e902c1e814362370203313131")
        sig = "FB CB BB 17 D1 EC 4F 1B 5B 4F 24 E5 3A 6C 70 E4 96 03 38 C3 48 DA 96 96 BF 5C B5 CE 73 42 E1 2C AD 4A 16 F5 56 FF CF 67 B4 86 FB B8 71 35 C5 99 19 46 C4 6D 1A 42 25 61 EC D6 7F 6B 12 D8 CE D2".replace(" ", "")
        sig_bytes = bytes.fromhex(sig)
        print(validate_signature(k, data_str, sig_bytes))

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
    "rsa_public_key_to_bytes_der",
    "rsa_public_key_from_bytes_der",
    "rsa_encrypt",
]
