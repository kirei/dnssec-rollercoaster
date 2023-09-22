import logging
from dataclasses import dataclass
from typing import Optional, Union

import dns.dnssec
import dns.rdatatype
import dns.zone
import dns.zonefile
from dns.dnssecalgs import GenericPrivateKey, get_algorithm_cls
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag

logger = logging.getLogger(__name__)


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
    Algorithm.PRIVATEDNS: "PrivateDNS",
}


@dataclass
class KeyPair:
    algorithm: Algorithm
    private_key: GenericPrivateKey
    ksk: bool = False
    revoked: bool = False
    sign: bool = False
    publish: bool = False
    keytag: Optional[int] = None
    name: Optional[str] = None
    algorithm_prefix: Optional[str] = None

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
        return self.private_key.public_key().to_dnskey(flags=self.flags)

    def as_dict(self, export: bool = True) -> dict:
        res = {
            "name": self.name,
            "algorithm": self.algorithm,
            "keytag": self.keytag,
            "ksk": self.ksk,
            "sign": self.sign,
            "publish": self.publish,
            "revoked": self.revoked,
            "private_key": self.private_key.to_pem().decode(),
        }
        if self.algorithm_prefix:
            res["algorithm_prefix"] = str(self.algorithm_prefix)
        if not export:
            res["algorithm_name"] = self.algorithm_name
        return res

    @classmethod
    def from_dict(cls, data: dict):
        algorithm = Algorithm(data["algorithm"])
        algorithm_prefix = data.get("algorithm_prefix")
        algorithm_cls = get_algorithm_cls(
            algorithm,
            dns.name.from_text(algorithm_prefix) if algorithm_prefix else None,
        )
        private_key = algorithm_cls.from_pem(data["private_key"].encode())
        return cls(
            algorithm=algorithm,
            algorithm_prefix=algorithm_prefix,
            private_key=private_key,
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
        algorithm: Union[str, int, Algorithm],
        key_size: Optional[int] = None,
        ksk: bool = False,
        name: Optional[str] = None,
        algorithm_prefix: Optional[str] = None,
    ):
        if isinstance(algorithm, str):
            algorithm = Algorithm[algorithm.upper()]
        if not isinstance(algorithm, Algorithm):
            algorithm = Algorithm(int(algorithm))
        kwargs = {}
        if key_size:
            kwargs["key_size"] = key_size
        algorithm_cls = get_algorithm_cls(
            algorithm,
            dns.name.from_text(algorithm_prefix) if algorithm_prefix else None,
        )
        private_key = algorithm_cls.generate(**kwargs)
        res = cls(
            name=name,
            algorithm=algorithm,
            private_key=private_key,
            ksk=ksk,
            algorithm_prefix=algorithm_prefix,
        )
        res.keytag = dns.dnssec.key_id(res.dnskey)
        logger.debug(
            "Generated %s (%d) keytag=%d, ksk=%s",
            res.algorithm.name,
            res.algorithm,
            res.keytag,
            res.ksk,
        )
        return res
