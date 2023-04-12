import argparse

import dns.dnssec
import dns.rdatatype
import dns.zone
import dns.zonefile
from dns.dnssectypes import DSDigest
from dns.rdtypes.dnskeybase import Flag


def main() -> None:
    parser = argparse.ArgumentParser(description="Zone Trust Anchor")
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
        "--ds",
        metavar="filename",
        required=False,
        help="DS trust anchors filename",
    )

    args = parser.parse_args()

    zone = dns.zone.from_file(open(args.input), origin=args.origin, relativize=False)

    dnskey_rrset = zone.get_rrset(zone.origin, dns.rdatatype.DNSKEY)

    ds_rdatasets = []

    for rdata in dnskey_rrset:
        if rdata.flags & Flag.SEP:
            ds_rdatasets.append(
                dns.dnssec.make_ds(
                    name=args.origin, key=rdata, algorithm=DSDigest.SHA256
                )
            )

    ds = dns.rrset.from_rdata_list(args.origin, dnskey_rrset.ttl, ds_rdatasets)

    if args.ds:
        with open(args.ds, "wt") as fp:
            fp.write(ds.to_text())
    else:
        print(ds.to_text())


if __name__ == "__main__":
    main()
