#!/usr/bin/env python3

"""

Copyright (C) 2026 github.com/mr-manuel
All rights reserved.

License: BSD 2-Clause

Fetches Wireshark's manuf database and converts it to the "prefix,vendor"
CSV format arpndplogging.py's mac_vendor_check() expects. Run from CI
(.github/workflows/update-oui.yml) to publish a copy of the database that
doesn't depend on a third-party site being reachable/unblocked at runtime
on the firewall.

"""

import argparse
import csv
import sys
import urllib.request

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"

# Prefixes that will never appear in the IEEE-registered manuf feed because
# they're locally-administered (U/L bit set) rather than assigned OUIs, but
# are common enough on a home/lab network to be worth labeling anyway.
EXTRA_VENDORS = {
    "525400": "QEMU/KVM (libvirt)",
    "0a0027": "VirtualBox (host-only)",
}


def fetch_manuf(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_manuf(text):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        fields = [f.strip() for f in line.split("\t") if f.strip()]
        if len(fields) < 2:
            continue

        # Strip a "/28"-style mask suffix on extended (non-24-bit) entries -
        # arpndplogging.py's mac_vendor_check() only ever matches on the
        # first 24/28/32 bits of a MAC anyway, so the mask itself isn't
        # meaningful to it, just the prefix hex.
        prefix = fields[0].split("/")[0].replace(":", "").replace("-", "").lower()
        if not prefix:
            continue

        # Column 3 (long organization name) is more identifiable than
        # column 2 (short mnemonic) when present
        vendor = fields[2].strip() if len(fields) >= 3 else fields[1].strip()
        if vendor:
            yield prefix, vendor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="Path to write the CSV to")
    args = parser.parse_args()

    manuf_text = fetch_manuf(MANUF_URL)

    vendors = {}
    for prefix, vendor in parse_manuf(manuf_text):
        # manuf lists entries in a stable, curated order - keep the first
        # (most specific/canonical) entry seen for a given prefix
        vendors.setdefault(prefix, vendor)

    if len(vendors) < 1000:
        # Checked before EXTRA_VENDORS is merged in, so this reflects the
        # fetched feed's own health. A malformed/near-empty response (e.g.
        # an error page served with a 200 status) should fail the workflow
        # loudly rather than silently publish a near-useless database.
        print(
            f"Only parsed {len(vendors)} vendor entries, expected tens of "
            "thousands - refusing to publish, source may be malformed",
            file=sys.stderr,
        )
        raise SystemExit(1)

    vendors.update(EXTRA_VENDORS)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for prefix in sorted(vendors):
            writer.writerow([prefix, vendors[prefix]])

    print(f"Wrote {len(vendors)} entries to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
