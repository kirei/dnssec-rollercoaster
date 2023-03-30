import argparse
import functools

import dns.dnssec
import dns.rdatatype
import dns.zone
import dns.zonefile
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from dns.dnssectypes import Algorithm
from dns.rdtypes.dnskeybase import Flag

from rollercoaster.keypair import KEY_GENERATORS


def generate_key(spec: dict):
    alg = Algorithm[spec["alg"].upper()]
    kwargs = {}
    if key_size := spec.get("size"):
        kwargs["key_size"] = key_size
    return (alg, KEY_GENERATORS[alg](**kwargs))


def main() -> None:
    parser = argparse.ArgumentParser(description="Zone Signer")
    parser.add_argument(
        "--origin",
        metavar="domain",
        default=".",
        help="Zone origin",
    )
    parser.add_argument(
        "--input",
        metavar="filename",
        required=True,
        help="Signed zone filename",
    )
    parser.add_argument(
        "--output",
        metavar="filename",
        help="Unsigned zone filename",
    )

    args = parser.parse_args()

    keyspec = [
        {"alg": "RSASHA256", "size": 2048, "ksk": True, "sign": True},
        {"alg": "RSASHA256", "size": 2048, "ksk": False, "sign": True},
        {"alg": "RSASHA256", "size": 2048, "ksk": False, "sign": False},
        {"alg": "ECDSAP256SHA256", "ksk": True, "sign": True},
        {"alg": "ECDSAP256SHA256", "ksk": False, "sign": True},
        {"alg": "ECDSAP256SHA256", "ksk": False, "sign": False},
    ]

    keys = []
    dnskeys = []
    for k in keyspec:
        algorithm, private_key = generate_key(k)
        flags = Flag.ZONE
        if k.get("ksk", False):
            flags |= Flag.SEP
        if k.get("revoke", False):
            flags |= Flag.REVOKE
        dnskey = dns.dnssec.make_dnskey(
            public_key=private_key.public_key(), algorithm=algorithm, flags=flags
        )
        dnskeys.append(dnskey)
        if k.get("sign", False):
            keys.append((private_key, dnskey))

    lifetime = 86400
    dnskey_ttl = 86400

    zone = dns.zone.from_file(open(args.input), origin=args.origin, relativize=False)

    with zone.writer() as txn:
        for dnskey in dnskeys:
            txn.add(zone.origin, dnskey_ttl, dnskey)
        dns.dnssec.sign_zone(
            zone=zone, add_dnskey=False, keys=keys, lifetime=lifetime, txn=txn
        )

    if args.output:
        with open(args.output, "wt") as fp:
            zone.to_file(fp)
    else:
        print(zone.to_text(relativize=False))


if __name__ == "__main__":
    main()
