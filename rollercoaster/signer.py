import argparse
import logging
import os
import time
import tomllib
from datetime import timedelta
from typing import List, Optional, Tuple

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.zone
import dns.zonefile
from dns.dnssectypes import Algorithm, DSDigest
from dns.rdtypes.ANY.TXT import TXT
from dns.rdtypes.dnskeybase import Flag

import rollercoaster.keyring
from rollercoaster import QUARTER_COUNT, SLOTS_PER_QUARTER
from rollercoaster.render import render_html
from rollercoaster.utils import cmtimer

DEFAULT_SLOT_TIMEDELTA = timedelta(seconds=30)
DEFAULT_DNSKEY_TTL = 60
DEFAULT_LIFETIME = 3600

logger = logging.getLogger(__name__)


def get_current_qs(
    td: timedelta = DEFAULT_SLOT_TIMEDELTA,
    t: Optional[int] = None,
) -> Tuple[int, int]:
    slot_length = td.total_seconds()
    t = t or int(time.time())
    n = t // slot_length % (QUARTER_COUNT * SLOTS_PER_QUARTER)
    q = int(n // SLOTS_PER_QUARTER)
    s = int(n % SLOTS_PER_QUARTER)
    return q + 1, s + 1


def get_next_qs(td: timedelta = DEFAULT_SLOT_TIMEDELTA) -> Tuple[int, int]:
    slot_length = td.total_seconds()
    t1 = int(time.time())
    t2 = t1 // slot_length * slot_length + slot_length
    w = t2 - t1
    logger.info("Waiting %d seconds for next slot", w)
    time.sleep(w)
    return get_current_qs(td=td, t=t2)


def get_zone_trust_anchors(zone: dns.zone.Zone) -> dns.rrset.RRset:
    dnskey_rrset = zone.get_rrset(zone.origin, dns.rdatatype.DNSKEY)
    ds_rdatasets = []
    for rdata in dnskey_rrset:
        if rdata.flags & Flag.SEP and not rdata.flags & Flag.REVOKE:
            ds_rdatasets.append(
                dns.dnssec.make_ds(
                    name=zone.origin, key=rdata, algorithm=DSDigest.SHA256
                )
            )
    return dns.rrset.from_rdata_list(zone.origin, dnskey_rrset.ttl, ds_rdatasets)


def prepare_zone(
    zone: dns.zone.Zone, hints_rrsets: Optional[List[dns.rrset.RRset]] = None
):
    """Prepare zone by removing signatures and replace hints"""

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
    with zone.writer() as txn:
        for name, rdataset in txn.iterate_rdatasets():
            if rdataset.rdtype in exclude_rdtypes:
                txn.delete(name, rdataset)
            elif (
                hints_rrsets
                and name == zone.origin
                and rdataset.rdtype == dns.rdatatype.NS
            ):
                exclude_glue.update([rr.target for rr in rdataset])
                txn.delete(name, rdataset)
        for name in exclude_glue:
            txn.delete(name, zone.rdclass, dns.rdatatype.A)
            txn.delete(name, zone.rdclass, dns.rdatatype.AAAA)
        for rrset in hints_rrsets:
            txn.add(rrset)


def get_keyring(config: dict) -> rollercoaster.keyring.KeyRing:
    """Generate keyring"""

    mode = config.get("mode", "double")
    if mode == "double":
        keyring_cls = rollercoaster.keyring.KeyRingDoubleSigner
    elif mode == "single":
        keyring_cls = rollercoaster.keyring.KeyRingSingleSigner
    else:
        raise ValueError("Unknown mode")

    logger.info("Signing using %s", keyring_cls.__name__)

    if algorithms := config.get("algorithms"):
        keyspecs = [{**algorithms["1"]}, {**algorithms["2"]}]
    else:
        keyspecs = [
            {"algorithm": Algorithm.RSASHA256, "key_size": 2048},
            {"algorithm": Algorithm.ECDSAP256SHA256},
        ]

    for k in keyspecs:
        if isinstance(k["algorithm"], str):
            k["algorithm"] = Algorithm[k["algorithm"].upper()]
    return keyring_cls(filename=config["keyring"], keyspecs=keyspecs)


def main():
    parser = argparse.ArgumentParser(description="DNSSEC Rollercoaster")
    parser.add_argument(
        "--config-file", dest="config_file", type=str, default="rollercoaster.toml"
    )
    parser.add_argument(
        "--config-section", dest="config_section", type=str, default="default"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debugging")
    parser.add_argument("--loop", action="store_true", help="Continuous signing")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    with open(args.config_file, "rb") as fp:
        config = tomllib.load(fp)

    if hints := config[args.config_section].get("hints"):
        with open(hints) as fp:
            hints_rrsets = dns.zonefile.read_rrsets(fp.read())
    else:
        hints_rrsets = None

    if filename := config[args.config_section].get("upstream"):
        with cmtimer("Prepare zone", logger=logger):
            zone = dns.zone.from_file(
                open(filename),
                origin=config[args.config_section]["origin"],
                relativize=False,
            )
            prepare_zone(zone, hints_rrsets)
            with open(config[args.config_section]["unsigned"], "wt") as fp:
                zone.to_file(fp)

    keyring = get_keyring(config[args.config_section])

    td = timedelta(seconds=config["delta"])
    refresh = (int(td.total_seconds()) // 5) or 5

    dnskey_ttl = config[args.config_section].get("dnskey_ttl", DEFAULT_DNSKEY_TTL)
    lifetime = config[args.config_section].get("lifetime", DEFAULT_LIFETIME)

    quarter, slot = get_current_qs(td)

    while True:
        with cmtimer("Loading zone"):
            zone = dns.zone.from_file(
                open(config[args.config_section]["unsigned"]),
                origin=config[args.config_section]["origin"],
                relativize=False,
            )

        logger.info("Starting quarter %d slot %d", quarter, slot)

        keyring.generate(quarter, slot)
        keyring.update(quarter, slot)

        keyring.print_state()

        with zone.writer() as txn:
            txn.replace(
                dns.name.Name(["_rollercoaster"]) + zone.origin,
                0,
                TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [f"q{quarter}s{slot}"]),
            )

        with cmtimer("Signing zone", logger=logger):
            keyring.sign_zone(zone, lifetime=lifetime, dnskey_ttl=dnskey_ttl)

        if filename := config[args.config_section].get("signed"):
            with open(filename, "wt") as fp:
                with cmtimer("Saving zone", logger=logger):
                    zone.to_file(fp)
            logger.info("Saved signed zone to %s", filename)

        if quarter == 4 and slot == 9:
            logger.info("Rotate keys")
            keyring.rotate()

        keyring.save()

        if anchors := config[args.config_section].get("anchors"):
            logger.info("Saving trust anchors to %s", anchors)
            ds = get_zone_trust_anchors(zone)
            with open(anchors, "wt") as fp:
                fp.write(ds.to_text())

        if dashboard := config[args.config_section].get("dashboard"):
            logger.info("Render dashboard to %s", dashboard)
            with open(dashboard, "wt") as fp:
                fp.write(
                    render_html(
                        keyring,
                        delta=td,
                        refresh=refresh,
                        current_quarter=quarter,
                        current_slot=slot,
                    )
                )

        if reload_command := config[args.config_section].get("reload"):
            logger.info("Executing reload command")
            os.system(reload_command)

        if not args.loop:
            break

        quarter, slot = get_next_qs(td)


if __name__ == "__main__":
    main()
