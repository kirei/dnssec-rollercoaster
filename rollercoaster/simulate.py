from dns.dnssectypes import Algorithm

from rollercoaster.keyring import KeyRing
from rollercoaster.render import render_html, render_text

KEYS_FILENAME = "keyring.json"


# logging.basicConfig(level=logging.DEBUG)

keyring = KeyRing(
    # filename=KEYS_FILENAME,
    keyspecs=[
        {"algorithm": Algorithm.RSASHA256, "key_size": 2048},
        {"algorithm": Algorithm.ECDSAP256SHA256},
    ],
)


print(render_text(keyring))

with open("dashboard.html", "wt") as fp:
    fp.write(render_html(keyring, current_quarter=1, current_slot=3))
