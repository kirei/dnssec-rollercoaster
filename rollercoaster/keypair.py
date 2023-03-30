import functools
import logging
from dataclasses import dataclass
from typing import Optional, Union

import cryptography.hazmat.primitives.serialization as serialization
import dns.dnssec
import dns.rdatatype
import dns.zone
import dns.zonefile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag

logger = logging.getLogger(__name__)

RSA_GENERATOR = functools.partial(
    rsa.generate_private_key, backend=default_backend(), public_exponent=65537
)

KEY_GENERATORS = {
    Algorithm.RSAMD5: RSA_GENERATOR,
    Algorithm.DSA: dsa.generate_private_key,
    Algorithm.RSASHA1: RSA_GENERATOR,
    Algorithm.DSANSEC3SHA1: dsa.generate_private_key,
    Algorithm.RSASHA1NSEC3SHA1: RSA_GENERATOR,
    Algorithm.RSASHA256: RSA_GENERATOR,
    Algorithm.RSASHA512: RSA_GENERATOR,
    Algorithm.ECDSAP256SHA256: functools.partial(
        ec.generate_private_key, curve=ec.SECP256R1
    ),
    Algorithm.ECDSAP384SHA384: functools.partial(
        ec.generate_private_key, curve=ec.SECP384R1
    ),
    Algorithm.ED25519: ed25519.Ed25519PrivateKey.generate,
    Algorithm.ED448: ed448.Ed448PrivateKey.generate,
}

PRETTY_ALGORTIHM = {
    Algorithm.RSAMD5: "RSA/MD5",
    Algorithm.DSA: "DSA",
    Algorithm.RSASHA1: "RSA/SHA1",
    Algorithm.DSANSEC3SHA1: "DSA/SHA1/NSEC3",
    Algorithm.RSASHA1NSEC3SHA1: "RSA/SHA1/NSEC3",
    Algorithm.RSASHA256: "RSA/SHA-256",
    Algorithm.RSASHA512: "RSA/SHA-512",
    Algorithm.ECDSAP256SHA256: "ECDSA/P-256/SHA-256",
    Algorithm.ECDSAP384SHA384: "ECDSA/P-384/SHA-384",
    Algorithm.ED25519: "Ed25519",
    Algorithm.ED448: "Ed448",
}


@dataclass
class KeyPair:
    algorithm: Algorithm
    private_key: dns.dnssec.PrivateKey
    ksk: bool = False
    revoked: bool = False
    sign: bool = False
    publish: bool = False
    keytag: Optional[int] = None
    name: Optional[str] = None

    @property
    def flags(self) -> int:
        return (
            Flag.ZONE
            | (Flag.REVOKE if self.revoked else 0)
            | (Flag.SEP if self.ksk else 0)
        )

    @property
    def algorithm_name(self) -> str:
        return PRETTY_ALGORTIHM.get(self.algorithm, self.algorithm.name)

    @property
    def dnskey(self) -> DNSKEY:
        return dns.dnssec.make_dnskey(
            public_key=self.private_key.public_key(),
            algorithm=self.algorithm,
            flags=self.flags,
        )

    def as_dict(self, export: bool = True) -> dict:
        res = {
            "name": self.name,
            "algorithm": self.algorithm,
            "keytag": self.keytag,
            "ksk": self.ksk,
            "sign": self.sign,
            "publish": self.publish,
            "revoked": self.revoked,
            "private_key": self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
        }
        if not export:
            res["algorithm_name"] = self.algorithm_name
        return res

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            algorithm=data["algorithm"],
            private_key=serialization.load_pem_private_key(
                data["private_key"].encode(), password=None
            ),
            ksk=data.get("ksk", False),
            revoked=data.get("revoked", False),
            sign=data.get("sign", True),
            publish=data.get("publish", True),
            keytag=data.get("keytag", False),
            name=data.get("name"),
        )

    @classmethod
    def generate(
        cls,
        algorithm: Union[str, Algorithm],
        key_size: Optional[int] = None,
        ksk: bool = False,
        name: Optional[str] = None,
    ):
        if isinstance(algorithm, str):
            algorithm = Algorithm[algorithm.upper()]
        kwargs = {}
        if key_size:
            kwargs["key_size"] = key_size
        private_key = KEY_GENERATORS[algorithm](**kwargs)
        res = cls(
            name=name,
            algorithm=algorithm,
            private_key=private_key,
            ksk=ksk,
        )
        res.keytag = dns.dnssec.key_id(res.dnskey)
        return res
