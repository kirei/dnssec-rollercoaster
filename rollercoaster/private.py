import cryptography.hazmat.primitives.serialization as serialization
import dns.dnssec
import dns.name
from dns.dnssecalgs.eddsa import PrivateED25519, PublicED25519
from dns.dnssectypes import Algorithm


class MyPublicKey(PublicED25519):
    algorithm = Algorithm.PRIVATEDNS
    name = "unknown.r00t-servers.net"

    def public_bytes(self) -> bytes:
        return dns.name.from_text(self.name).to_wire() + self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )


class MyPrivateKey(PrivateED25519):
    public_cls = MyPublicKey
