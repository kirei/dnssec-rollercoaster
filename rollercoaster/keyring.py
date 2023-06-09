import json
import logging
from typing import List, Optional

import dns.dnssec
import dns.zone

from rollercoaster.keypair import KeyPair

logger = logging.getLogger(__name__)


class KeyRing:
    def __init__(self, keyspecs: List[dict] = [], filename: Optional[str] = None):
        self.filename = filename
        self.keyspecs = keyspecs
        self.keypairs = None
        if self.filename:
            try:
                self.load(self.filename)
            except FileNotFoundError:
                logger.warning("Generating new keys")
        if self.keypairs is None:
            self.generate()

    def print_state(self):
        for a, keys in self.enumerate():
            for name, keypair in keys.items():
                if keypair.revoked:
                    logger.debug(
                        "%s (%d) %s REVOKED (keytag %d, flags %d, set %d)",
                        keypair.algorithm.name,
                        keypair.algorithm,
                        name,
                        keypair.keytag,
                        keypair.flags,
                        a,
                    )
                elif keypair.sign:
                    logger.debug(
                        "%s (%d) %s SIGNING (keytag %d, flags %d, set %d)",
                        keypair.algorithm.name,
                        keypair.algorithm,
                        name,
                        keypair.keytag,
                        keypair.flags,
                        a,
                    )
                elif keypair.publish:
                    logger.debug(
                        "%s (%d) %s PUBLISHED (keytag %d, flags %d, set %d)",
                        keypair.algorithm.name,
                        keypair.algorithm,
                        name,
                        keypair.keytag,
                        keypair.flags,
                        a,
                    )

    def enumerate(self):
        return enumerate(self.keypairs)

    def generate(self, quarter: Optional[int] = None, slot: Optional[int] = None):
        if self.keypairs is None:
            self.keypairs = [{} for _ in self.keyspecs]

        if quarter == 1 and slot == 1:
            del self.keypairs[1]["ksk"]
            del self.keypairs[1]["zsk-q1"]
            del self.keypairs[1]["zsk-q2"]
            del self.keypairs[1]["zsk-q3"]
            del self.keypairs[1]["zsk-q4"]
        if quarter == 1 and slot == 2:
            del self.keypairs[0]["zsk-q4"]

        for a, keyspec in enumerate(self.keyspecs):
            prefix = "a" + str(int(keyspec["algorithm"]))
            if "ksk" not in self.keypairs[a]:
                logger.info("Generating new KSK(%d)", a)
                self.keypairs[a]["ksk"] = KeyPair.generate(
                    name=f"{prefix}-ksk",
                    ksk=True,
                    **keyspec,
                )
            else:
                logger.debug("Keeping existing KSK(%d)", a)
            for q in range(1, 5):
                if f"zsk-q{q}" not in self.keypairs[a]:
                    logger.info("Generating new ZSK(%d) for quarter %d", a, q)
                    self.keypairs[a][f"zsk-q{q}"] = KeyPair.generate(
                        name=f"{prefix}-zsk-q{q}",
                        ksk=False,
                        **keyspec,
                    )
                else:
                    logger.debug("Keeping existing ZSK(%d) for quarter %d", a, q)

    def delete(self, keyset: int, quarter: int, ksk: bool = False):
        """Delete specific key (to trigger new key generation)"""
        name = "ksk" if ksk else f"zsk-q{quarter}"
        del self.keypairs[keyset][name]
        self.generate()

    def rotate(self):
        self.keypairs = [self.keypairs[1], self.keypairs[0]]
        self.keyspecs = [self.keyspecs[1], self.keyspecs[0]]

    def reset(self):
        """Disable publish, sign, revoked for all keys"""
        for a, keys in enumerate(self.keypairs):
            for key in keys.values():
                key.publish = False
                key.sign = False
                key.revoked = False

    def save(self, filename: Optional[str] = None) -> None:
        keyring_dict = {
            "keyspecs": self.keyspecs,
            "keys": [
                {name: key.as_dict() for name, key in keys.items()}
                for keys in self.keypairs
            ],
        }
        filename = filename or self.filename
        with open(filename, "wt") as fp:
            logger.info("Saving keys to %s", filename)
            json.dump(keyring_dict, fp, indent=4)

    def load(self, filename: str) -> None:
        with open(filename, "rt") as fp:
            logger.info("Loading keys from %s", filename)
            keyring_dict = json.load(fp)
        self.keyspecs = keyring_dict["keyspecs"]
        self.keypairs = [
            {
                name: KeyPair.from_dict(key_dict)
                for name, key_dict in keyring_dict.items()
            }
            for keyring_dict in keyring_dict["keys"]
        ]

    @classmethod
    def from_file(cls, filename: str):
        res = KeyRing()
        res.load(filename)
        return res

    def update(self, quarter: int, slot: int) -> None:
        """Update keyring based on quarter and slot"""

        self.reset()

        a1 = self.keypairs[0]
        a2 = self.keypairs[1]

        if quarter == 1:
            a1["ksk"].publish = True
            a1["ksk"].sign = True
            a1["zsk-q1"].publish = True
            a1["zsk-q1"].sign = True

            if slot == 1:
                # post-publication
                a1["zsk-q4"].publish = True

            if slot == 9:
                # pre-publication
                a1["zsk-q2"].publish = True

        elif quarter == 2:
            a1["ksk"].publish = True
            a1["ksk"].sign = True
            a1["zsk-q2"].publish = True
            a1["zsk-q2"].sign = True

            if slot == 1:
                # post-publication
                a1["zsk-q1"].publish = True

            if slot > 1:
                # introduce new KSK
                a2["ksk"].publish = True
                a2["ksk"].sign = True
                a2["zsk-q2"].publish = True
                a2["zsk-q2"].sign = True

            if slot == 9:
                # post-publication
                a1["zsk-q3"].publish = True
                a2["zsk-q3"].publish = True

        elif quarter == 3:
            a1["ksk"].publish = True
            a1["ksk"].sign = True
            a1["zsk-q3"].publish = True
            a1["zsk-q3"].sign = True

            a2["ksk"].publish = True
            a2["ksk"].sign = True
            a2["zsk-q3"].publish = True
            a2["zsk-q3"].sign = True

            if slot == 1:
                # post-publication
                a1["zsk-q2"].publish = True
                a2["zsk-q2"].publish = True
            if slot == 9:
                # pre-publication
                a1["zsk-q4"].publish = True
                a2["zsk-q4"].publish = True

        elif quarter == 4:
            a1["ksk"].publish = True
            a1["ksk"].sign = True
            a1["zsk-q4"].publish = True
            a1["zsk-q4"].sign = True

            a2["ksk"].publish = True
            a2["ksk"].sign = True
            a2["zsk-q4"].publish = True
            a2["zsk-q4"].sign = True

            if slot == 1:
                # post-publication
                a1["zsk-q3"].publish = True
                a2["zsk-q3"].publish = True

            if slot > 1:
                a1["zsk-q4"].publish = False
                a1["zsk-q4"].sign = False

            if slot > 1 and slot < 9:
                # revokation
                a1["ksk"].revoked = True

            if slot == 9:
                # pre-publication
                a1["ksk"].publish = False
                a1["ksk"].sign = False
                a2["zsk-q1"].publish = True

                # drop alg 1
                a1["ksk"].publish = False
                a1["ksk"].sign = False

    def sign_zone(
        self, zone: dns.zone.Zone, lifetime: int = 3600, dnskey_ttl: int = 60
    ):
        keypairs = []
        for _, k in enumerate(self.keypairs):
            keypairs.extend(k.values())

        keys = []
        dnskeys = []
        for keypair in keypairs:
            dnskey = keypair.dnskey
            if keypair.publish:
                dnskeys.append(dnskey)
            if keypair.sign:
                keys.append((keypair.private_key, dnskey))

        with zone.writer() as txn:
            for dnskey in dnskeys:
                txn.add(zone.origin, dnskey_ttl, dnskey)
            dns.dnssec.sign_zone(
                zone=zone,
                add_dnskey=False,
                keys=keys,
                lifetime=lifetime,
                txn=txn,
                policy=dns.dnssec.allow_all_policy,
            )


class KeyRingDoubleSigner(KeyRing):
    pass


class KeyRingSingleSigner(KeyRing):
    def update(self, quarter: int, slot: int) -> None:
        """Update keyring based on quarter and slot"""

        self.reset()

        a1 = self.keypairs[0]
        a2 = self.keypairs[1]

        if quarter == 1:
            a1["ksk"].publish = True
            a1["ksk"].sign = True
            a1["zsk-q1"].publish = True
            a1["zsk-q1"].sign = True

            if slot == 1:
                # post-publication
                a1["zsk-q4"].publish = True

            if slot == 9:
                # pre-publication
                a1["zsk-q2"].publish = True

        elif quarter == 2:
            a1["ksk"].publish = True
            a1["ksk"].sign = True
            a1["zsk-q2"].publish = True
            a1["zsk-q2"].sign = True

            if slot == 1:
                # post-publication
                a1["zsk-q1"].publish = True

            if slot > 1:
                # introduce new KSK
                a2["ksk"].publish = True
                a2["ksk"].sign = False
                a2["zsk-q2"].publish = False
                a2["zsk-q2"].sign = False

            if slot == 9:
                # post-publication
                a1["zsk-q3"].publish = True
                a2["zsk-q3"].publish = False

        elif quarter == 3:
            # a1["ksk"].publish = True
            # a1["ksk"].sign = True
            a1["zsk-q3"].publish = False
            a1["zsk-q3"].sign = False

            a2["ksk"].publish = True
            a2["ksk"].sign = True
            a2["zsk-q3"].publish = True
            a2["zsk-q3"].sign = True

            if slot == 1:
                # post-publication
                a1["ksk"].publish = True
                a1["zsk-q2"].publish = True
                a2["zsk-q2"].publish = False
            if slot == 9:
                # pre-publication
                a2["zsk-q4"].publish = True

        elif quarter == 4:
            a1["ksk"].publish = False
            a1["ksk"].sign = False
            a1["zsk-q4"].publish = False
            a1["zsk-q4"].sign = False

            a2["ksk"].publish = True
            a2["ksk"].sign = True
            a2["zsk-q4"].publish = True
            a2["zsk-q4"].sign = True

            if slot == 1:
                # post-publication
                # a1["ksk"].publish = True
                # a1["ksk"].sign = True
                a1["zsk-q3"].publish = False
                a2["zsk-q3"].publish = True

            if slot > 1:
                a1["zsk-q4"].publish = False
                a1["zsk-q4"].sign = False

            if slot > 1 and slot < 9:
                # revocation
                a1["ksk"].sign = True
                a1["ksk"].publish = True
                a1["ksk"].revoked = True

            if slot == 9:
                # pre-publication
                a1["ksk"].publish = False
                a1["ksk"].sign = False
                a2["zsk-q1"].publish = True

                # drop alg 1
                a1["ksk"].publish = False
                a1["ksk"].sign = False


class KeyRingHybridSigner(KeyRingDoubleSigner):
    def update(self, quarter: int, slot: int) -> None:
        """Update keyring based on quarter and slot"""

        super().update(quarter, slot)

        a2 = self.keypairs[1]

        if quarter == 1 or (quarter == 2 and slot == 1):
            a2["ksk"].publish = True
