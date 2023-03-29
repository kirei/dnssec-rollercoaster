import argparse
import functools

import dns.dnssec
import dns.rdatatype
import dns.zone
import dns.zonefile
from cryptography.hazmat.backends import default_backend

# from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from dns.dnssectypes import Algorithm
from dns.rdtypes.dnskeybase import Flag

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
        {"alg": "ED25519", "ksk": True, "sign": True},
        {"alg": "ED25519", "ksk": False, "sign": True},
        {"alg": "RSASHA256", "size": 2048, "ksk": True, "sign": True, "revoke": True},
        {"alg": "RSASHA256", "size": 2048, "ksk": False, "sign": True},
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
