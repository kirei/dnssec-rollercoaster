import cryptography.hazmat.primitives.serialization as serialization
import dns.dnssec
import dns.name
from cryptography.hazmat.primitives.asymmetric import ed25519

PRIVATE_ALGORITHM_NAME = dns.name.from_text("unknown.r00t-servers.net").to_wire()


class MyPublicKey(dns.dnssec.PrivateAlgorithmPublicKeyBase):
    name = PRIVATE_ALGORITHM_NAME

    def __init__(self, public_key: ed25519.Ed25519PublicKey):
        self.public_key = public_key

    def verify(self, signature: bytes, data: bytes):
        return self.public_key.verify(signature, data)

    def public_bytes(self) -> bytes:
        return self.name + self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )


class MyPrivateKey(dns.dnssec.PrivateAlgorithmPrivateKeyBase):
    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        self.private_key = private_key

    @classmethod
    def generate(cls):
        return cls(ed25519.Ed25519PrivateKey.generate())

    def public_key(self):
        return MyPublicKey(self.private_key.public_key())

    def private_bytes(self, *args, **kwargs) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)
