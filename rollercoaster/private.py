import cryptography.hazmat.primitives.serialization as serialization
import dns.dnssec
import dns.name
from cryptography.hazmat.primitives.asymmetric import ed25519


class MyPublicKey(dns.dnssec.PrivateAlgorithmPublicKeyBase):
    name = "unknown.r00t-servers.net"

    def __init__(self, public_key: ed25519.Ed25519PublicKey):
        self.public_key = public_key

    def verify(self, signature: bytes, data: bytes):
        return self.public_key.verify(signature, data)

    def public_bytes(self) -> bytes:
        return dns.name.from_text(self.name).to_wire() + self.public_key.public_bytes(
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
