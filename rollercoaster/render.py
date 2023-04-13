from collections import defaultdict
from typing import Optional

import jinja2

from rollercoaster import QUARTER_COUNT, SLOTS_PER_QUARTER
from rollercoaster.keyring import KeyRing


def render_text(keyring: KeyRing) -> str:
    res = {}
    for a, keys in keyring.enumerate():
        for n in keys.keys():
            res[f"a{a}-{n}"] = f"Algorithm {a}, {n:6}  "

    for quarter in range(1, 5):
        for slot in range(1, 10):
            keyring.update(quarter, slot)

            for a, keys in keyring.enumerate():
                for name, keypair in keys.items():
                    k = f"a{a}-{name}"

                    if keypair.revoked:
                        status = "R"
                    elif keypair.sign:
                        status = "S"
                    elif keypair.publish:
                        status = "P"
                    else:
                        status = " "
                    res[k] += f" {status}"
                    if slot == 9:
                        res[k] += " |"

    return "\n".join(res.values())


def render_html(
    keyring: KeyRing,
    refresh: int = 60,
    current_quarter: Optional[int] = None,
    current_slot: Optional[int] = None,
) -> str:
    rows = defaultdict(list)
    for quarter in range(1, QUARTER_COUNT + 1):
        for slot in range(1, SLOTS_PER_QUARTER + 1):
            keyring.update(quarter, slot)
            for a, keypairs in keyring.enumerate():
                for keypair in keypairs.values():
                    if keypair.revoked or keypair.sign or keypair.publish:
                        rows[keypair.name].append(keypair.as_dict(export=False))
                    else:
                        rows[keypair.name].append(None)

    for k, v in list(rows.items()):
        if v.count(None) == len(v):
            del rows[k]

    env = jinja2.Environment(
        loader=jinja2.PackageLoader("rollercoaster", "templates"),
        autoescape=jinja2.select_autoescape(),
    )
    template = env.get_template("dashboard.j2")
    return template.render(
        refresh=refresh,
        rows=rows,
        quarters=QUARTER_COUNT,
        slots=SLOTS_PER_QUARTER,
        current_quarter=current_quarter,
        current_slot=current_slot,
    )
