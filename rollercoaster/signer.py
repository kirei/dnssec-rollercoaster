import argparse
import logging
import time
import tomllib
from datetime import timedelta
from typing import Optional, Tuple

import dns.dnssec
import dns.rdatatype
import dns.zone
import dns.zonefile
from dns.dnssectypes import Algorithm

from rollercoaster import QUARTER_COUNT, SLOTS_PER_QUARTER
from rollercoaster.keyring import KeyRing
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
    logger.debug("Waiting %d seconds for next slot", w)
    time.sleep(w)
    return get_current_qs(td=td, t=t2)


def main():
    parser = argparse.ArgumentParser(description="DNS rollercoaster")
    parser.add_argument("--config", type=str, default="rollercoaster.toml")
    parser.add_argument("--debug", action="store_true", help="Enable debugging")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    with open(args.config, "rb") as fp:
        config = tomllib.load(fp)

    keyring = KeyRing(
        filename=config["keyring"],
        keyspecs=[
            {"algorithm": Algorithm.RSASHA256, "key_size": 2048},
            {"algorithm": Algorithm.ED25519},
        ],
    )

    td = timedelta(seconds=config["delta"])

    quarter, slot = get_current_qs(td)

    while True:
        with cmtimer("Loading zone"):
            zone = dns.zone.from_file(
                open(config["zone"]["unsigned"]),
                origin=config["zone"]["origin"],
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

        with cmtimer("Signing zone", logger=logger):
            keyring.sign_zone(zone)

        if quarter == 4 and slot == 9:
            logger.info("Flip keys")
            keyring.rotate()

        filename = config["zone"]["signed"]
        with open(filename, "wt") as fp:
            with cmtimer("Saving zone", logger=logger):
                zone.to_file(fp)
        logger.info("Saved signed zone to %s", filename)

        keyring.save()
        logger.debug("Keyring saved")

        quarter, slot = get_next_qs(td)


if __name__ == "__main__":
    main()
