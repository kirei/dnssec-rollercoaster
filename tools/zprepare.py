import argparse

import dns.rdatatype
import dns.zone
import dns.zonefile


def main() -> None:
    parser = argparse.ArgumentParser()
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
    parser.add_argument(
        "--ns",
        metavar="filename",
        help="Name server set",
    )

    args = parser.parse_args()

    exclude_rdtypes = set(
        [
            dns.rdatatype.DNSKEY,
            dns.rdatatype.RRSIG,
            dns.rdatatype.NSEC,
            dns.rdatatype.NSEC3,
            dns.rdatatype.NSEC3PARAM,
        ]
    )
    exclude_glue = set()

    if args.ns:
        with open(args.ns) as fp:
            ns_rrsets = dns.zonefile.read_rrsets(fp.read())
    else:
        ns_rrsets = None

    zone = dns.zone.from_file(open(args.input), origin=args.origin, relativize=False)

    with zone.writer() as txn:
        for name, rdataset in txn.iterate_rdatasets():
            if rdataset.rdtype in exclude_rdtypes:
                txn.delete(name, rdataset)
            elif (
                ns_rrsets
                and name == zone.origin
                and rdataset.rdtype == dns.rdatatype.NS
            ):
                exclude_glue.update([rr.target for rr in rdataset])
                txn.delete(name, rdataset)
        for name in exclude_glue:
            txn.delete(name, zone.rdclass, dns.rdatatype.A)
            txn.delete(name, zone.rdclass, dns.rdatatype.AAAA)
        for rrset in ns_rrsets:
            txn.add(rrset)

    if args.output:
        with open(args.output, "wt") as fp:
            zone.to_file(fp)
    else:
        print(zone.to_text(relativize=False))


if __name__ == "__main__":
    main()
