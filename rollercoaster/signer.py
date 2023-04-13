import argparse
import logging
import os
import time
import tomllib
from datetime import timedelta
from typing import Optional, Tuple

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


def main():
    parser = argparse.ArgumentParser(description="DNS rollercoaster")
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

    mode = config[args.config_section].get("mode", "double")
    if mode == "double":
        keyring_cls = rollercoaster.keyring.KeyRingDoubleSigner
    elif mode == "single":
        keyring_cls = rollercoaster.keyring.KeyRingSingleSigner
    else:
        raise ValueError("Unknown mode")

    logger.info("Signing using %s", keyring_cls.__name__)

    keyring = keyring_cls(
        filename=config[args.config_section]["keyring"],
        keyspecs=[
            {"algorithm": Algorithm.RSASHA256, "key_size": 2048},
            {"algorithm": Algorithm.ECDSAP256SHA256},
        ],
    )

    td = timedelta(seconds=config["delta"])

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

        for a, keys in keyring.enumerate():
            for name, keypair in keys.items():
                if keypair.revoked:
                    logger.debug("%d %s REVOKED", keypair.algorithm, name)
                elif keypair.sign:
                    logger.debug("%d %s SIGNING", keypair.algorithm, name)
                elif keypair.publish:
                    logger.debug("%d %s PUBLISHED", keypair.algorithm, name)

        with zone.writer() as txn:
            txn.replace(
                dns.name.Name(["_rollercoaster"]) + zone.origin,
                0,
                TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [f"q{quarter}s{slot}"]),
            )

        with cmtimer("Signing zone", logger=logger):
            keyring.sign_zone(zone)

        if quarter == 4 and slot == 9:
            logger.info("Flip keys")
            keyring.rotate()

        filename = config[args.config_section]["signed"]
        with open(filename, "wt") as fp:
            with cmtimer("Saving zone", logger=logger):
                zone.to_file(fp)
        logger.info("Saved signed zone to %s", filename)

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
                    render_html(keyring, current_quarter=quarter, current_slot=slot)
                )

        if reload_command := config[args.config_section].get("reload"):
            logger.info("Executing reload command")
            os.system(reload_command)

        if not args.loop:
            break

        quarter, slot = get_next_qs(td)


if __name__ == "__main__":
    main()
